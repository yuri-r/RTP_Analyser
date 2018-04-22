#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use LWP::Simple qw(getstore);
#use Time::HiRes qw(usleep nanosleep gettimeofday time);
use DateTime;
use DateTime::Duration;
use threads;
use Thread::Queue;
use POSIX;
#use Proc::Daemon;

#Proc::Daemon::Init;
open STDERR, '>/var/log/rtp_analyser/rtp_analyser.err';

use lib '/usr/local/rtp_analyser';
use common_facilities qw($logger %CONFIG_PARAM $tshark_ob_filter);
use vars qw($http_ua $json_obj 
            $analysis_start_time 
            $silent_calls_counter 
            $no_rtp_counter 
            $period_to_analyze 
            $time_back_to_analize 
            $to_date
            $from_date
            $cdrs_queue_in
            $cdrs_queue_out
            $pcaps_queue);

$json_obj               = JSON->new->allow_nonref;
$http_ua                = LWP::UserAgent->new(timeout => 600);
$period_to_analyze      = DateTime::Duration->new( seconds => $CONFIG_PARAM{'PERIOD_TO_ANALYZE'});
$time_back_to_analize   = DateTime::Duration->new( seconds => $CONFIG_PARAM{'TIME_BACK_TO_ANALYZE'});
$cdrs_queue_in          = Thread::Queue->new();    
$cdrs_queue_out         = Thread::Queue->new();


my $pattern             = 'c2:15:5b:65:13:1c:68:68:20:79:fa:b4:81:09:11:20:00:03:b3:60:ae:04:46:00:00:25:f1:1e:53:9d:d0\n';
my $sid                 = connect_to_vm();
my $cookie              = 'PHPSESSID='.$sid;

#my $continue = 1;
#$SIG{TERM} = sub { $continue = 0 };

while (1) {
    my $analysis_time = get_cdrs($cookie);
    if ($analysis_time < $CONFIG_PARAM{'PERIOD_TO_ANALYZE'}) {
        my $time_to_sleep = $CONFIG_PARAM{'PERIOD_TO_ANALYZE'} - $analysis_time;
        sleep($time_to_sleep);
    }
    else {
        $logger->info("It took so long to analyse RTP. Preconfigured PERIOD_TO_ANALYZE: ".$CONFIG_PARAM{'PERIOD_TO_ANALYZE'}.", The analysis took: ".$analysis_time.". Try to decrease the number of CDRs per thread (the current value is ".$CONFIG_PARAM{'NUM_OF_CDRS_PER_THR'}.")");
        sleep(1);
    }
}

##########################################################################################
# Extract Payload From RTP
sub find_pattern_in_rtp_payload{
    my ($rtp_payload, $cdr_data) = @_;
    my $cdr_id       = ${$cdr_data}[0];
    my $cdr_url      = ${$cdr_data}[1];
    my $splunk_info  = ${$cdr_data}[2];
    
    my $num_of_rtp_payload_packets          = $rtp_payload =~ tr/\n//;
    my $num_of_silent_rtp_payload_packets   = () = $rtp_payload =~ /$pattern/g;

    $logger->debug("Total number of RTP packets in PCAP file in CDR ".$cdr_id.": ".$num_of_rtp_payload_packets . $splunk_info);
    $logger->debug("Number of silent RTP packets in PCAP file in CDR ".$cdr_id.": ".$num_of_silent_rtp_payload_packets . $splunk_info);
    
    if (0 == $num_of_rtp_payload_packets) {
        $logger->info("No RTP packets in PCAP file in CDR ".$cdr_id.". URL to CDR on VM: ".$cdr_url . $splunk_info);
        $no_rtp_counter++;
        return	    
    }
    
    if ($num_of_silent_rtp_payload_packets/$num_of_rtp_payload_packets > 0.8) {
        $logger->info("The PCAP file in CDR ".$cdr_id." contains silence. URL to CDR on VM: ".$cdr_url . $splunk_info);
        $silent_calls_counter++;
    }
    else {
        $logger->debug("The PCAP file in CDR ".$cdr_id." contains audio".$splunk_info);
    }
    
    return	    
}

##########################################################################################
# Get CDRs
sub get_cdrs
{
    my ($cookie) = @_;
    
    $to_date             = DateTime->now - $time_back_to_analize;
    $from_date           = $to_date - $period_to_analyze;
    my $analysis_start_time = time();

    #remove temporary pcap files
    `rm -f $CONFIG_PARAM{'TMP_PCAP_LOCATION'}*`;
    $logger->info("Retrieving CDRs from VM from " .$from_date." to ".$to_date);
    
    my $get_cdrs_url = $CONFIG_PARAM{'GET_CDRS_URL'}."&fdatefrom=".$from_date."&fdateto=".$to_date."&fcaller_domain=".$CONFIG_PARAM{'CALLER_DOMAINS'}."&fsipcalledip=".$CONFIG_PARAM{'OB_IPs'}."&fsipcallerdip_type=1&fsipresponse=200&fdurationgt=".$CONFIG_PARAM{'MIN_CALL_DURATION'}."&fdurationlt=".$CONFIG_PARAM{'MAX_CALL_DURATION'}."&fsensor_id=18&fcodec=".$CONFIG_PARAM{'PAYLOAD_CODEC'}."&suppress_results=0";  
    my $http_body    = $http_ua->post($get_cdrs_url, 'Cookie' => $cookie);  
    
    $logger->debug("CDR URL: ".$get_cdrs_url);
    
    if (!defined($http_body)) {
        $logger->error("No response from VM");
        return;
    }

    $logger->debug("Extracting JSON body from VM response");
    
    my $json_body = undef;
    eval { $json_body = $json_obj->decode($http_body->content); };
    if ($@ || !defined($json_body)) {
        $logger->error("Failed to retrieve CDR from VM. ".$http_body->content);
        return;        
    }

    if (!defined($json_body->{results})) {
        $logger->info("No CDR records in VM response, the following CDR filter was applied: ".$get_cdrs_url);
        return;        
    }
    
    my @cdrs_array = @{$json_body->{results}};
    my $num_of_cdrs = $json_body->{total};
    my $cdr_url = undef;
    my $corr_id = undef;
    $silent_calls_counter = 0;
    $no_rtp_counter = 0;

    $logger->info("Retrieved ".$num_of_cdrs." CDRs from " .$from_date." to ".$to_date.". Starting analysis...");
    
    
    foreach my $cdr (@cdrs_array) {
		$corr_id = $cdr->{'custom_header__Comm-Correlation-ID'};
        my $corr_id_escaped_chars = $corr_id;
        $corr_id_escaped_chars =~ s/#/%23/g;
        $cdr_url = "http://voipmonitor/admin.php?cdr_filter={\"fdatefrom\":\"".$from_date."\",\"fdateto\":\"".$to_date."\",\"fcustom_header__Comm-Correlation-ID\":\"".$corr_id_escaped_chars."\"}&cdr_group_data={\"group_by\":4}";
        
        my $splunk_info = "; ExternalTransactionId=[".$corr_id."]; SrcNumber=[".$cdr->{caller}."]; DstNumber=[".$cdr->{called}."]";
        my @cdr_data = ($cdr->{ID}, $cdr_url, $splunk_info);
        $cdrs_queue_in->enqueue(\@cdr_data);
#       get_pcap($cdr->{ID}, $cdr->{'custom_header__Comm-Correlation-ID'}, $from_date, $to_date);
    }   
    
    my $thr_pool_size = ceil($num_of_cdrs/$CONFIG_PARAM{'NUM_OF_CDRS_PER_THR'});
    
    foreach(1..$thr_pool_size)  #undef is a marker for each thread
    {
        $cdrs_queue_in->enqueue(undef);
    }

    my @get_pcaps_thr_pool = map{
        threads->new(\&get_pcap_by_cdr_id)
    } 1 .. $thr_pool_size;

    extract_rtp_from_pcaps($thr_pool_size, $corr_id);
    
    my $analysis_time = time() - $analysis_start_time;;

    $logger->info("Analysed ".$num_of_cdrs." CDRs, number of silent calls: ".$silent_calls_counter.", number of calls without rtp: ".$no_rtp_counter.", counters summary (total/silent/no rtp): ".$num_of_cdrs."/".$silent_calls_counter."/".$no_rtp_counter.", analisys time ".$analysis_time."s, the following CDR filter was applied: ".$get_cdrs_url);
    
    foreach(@get_pcaps_thr_pool)
    {
        $_->join;
    }
    
    return $analysis_time;
}

##########################################################################################
# Get PCAP by CDR id
sub get_pcap_by_cdr_id
{
	while(my $cdr_data = $cdrs_queue_in->dequeue())
	{        
        $logger->debug("Queue Size: " . $cdrs_queue_in->pending);
		my $cdr_id       = ${$cdr_data}[0];
		my $cdr_url      = ${$cdr_data}[1];
        my $splunk_info  = ${$cdr_data}[2];    
        my $get_pcap_url = $CONFIG_PARAM{'GET_PCAP_URL'}."?id=".$cdr_id;
        
        $logger->debug("Get PCAP by CDR ID: ".$get_pcap_url.", Thread ID: ".threads->tid);
        
        my $pcap = $http_ua->get($get_pcap_url, 'Cookie' => $cookie);
        my $content_type = $pcap->header("Content-Type");

        if (!defined($pcap)) {
            $logger->info("No PCAP in CDR. URL to CDR on VM: ".$cdr_url.$splunk_info);
            next;
        }
        
        my $pcap_content = $pcap->decoded_content;

        if ($content_type eq "text/html") {
            $logger->info($pcap_content." CDR ID: ".$cdr_id.". URL to CDR on VM: ".$cdr_url.$splunk_info);     #The PCAP is not in DB yet. Try reload again later.
            next;
        }    

        my $pcap_file = $CONFIG_PARAM{'TMP_PCAP_LOCATION'}.$cdr_id.".pcap";
        my $pcap_rtp_file = $CONFIG_PARAM{'TMP_PCAP_LOCATION'}.$cdr_id."_rtp.pcap";
        
        open my $fh, ">", $pcap_file;
        print {$fh} $pcap_content;
        close $fh;
        
        my $src_rtp_ip_port = `tshark -nr $pcap_file -R $tshark_ob_filter -T fields -e sdp.connection_info.address -T fields -e sdp.media.port`;
        
        if (defined($src_rtp_ip_port)) {
            my ($src_rtp_ip, $src_rtp_port) = split(" ", $src_rtp_ip_port);
            ${$cdr_data}[3] = $src_rtp_port;
            
#            $logger->debug("CDR ID: ".$cdr_id.", Source RTP IP/Port: ".$src_rtp_ip."/".$src_rtp_port.$splunk_info);
            
            `tshark -nr $pcap_file -R ip.src==$src_rtp_ip -w $pcap_rtp_file`;

#            my $rtp_payload = `tshark -nr $pcap_rtp_file -d udp.port==$src_rtp_port,rtp -R rtp -T fields -e rtp.payload`;
#            $logger->info("tshark -nr $pcap_rtp_file -d udp.port==$src_rtp_port,rtp -R rtp -T fields -e rtp.payload");

#            find_pattern_in_rtp_payload($rtp_payload, $cdr_id, $cdr_url);
        }
        else {
            $logger->error("Failed to extract RTP from corrupted PCAP file ".$pcap_file.", CDR ID: ".$cdr_id.$splunk_info);
            next;
        }
            
            
        $cdrs_queue_out->enqueue($cdr_data);
	}
    
    $cdrs_queue_out->enqueue(undef);
}

##########################################################################################
# Extract RTP from PCAPs
sub extract_rtp_from_pcaps
{
    my ($thr_pool_size, $corr_id) = @_;

    my $thr_counter = 0;
  	while(1)
	{
        my $cdr_data = $cdrs_queue_out->dequeue();
        if (defined($cdr_data)) {
            my $cdr_id       = ${$cdr_data}[0];
            my $src_rtp_port = ${$cdr_data}[3];
            my $pcap_rtp_file = $CONFIG_PARAM{'TMP_PCAP_LOCATION'}.$cdr_id."_rtp.pcap";

            my $rtp_payload = `tshark -nr $pcap_rtp_file -d udp.port==$src_rtp_port,rtp -R rtp -T fields -e rtp.payload`;

            find_pattern_in_rtp_payload($rtp_payload, $cdr_data);
        }
        else {
            $thr_counter++;
            if ($thr_counter == $thr_pool_size) {
                last;
            }
        }
    }    

    return;
}

##########################################################################################
# Get VM Session ID
sub connect_to_vm
{
    $logger->info("Connecting to VM...");
    $logger->debug("VM login URL: ".$CONFIG_PARAM{'LOGIN_URL'});
    
    my $http_resp = $http_ua->get($CONFIG_PARAM{'LOGIN_URL'});

    if ($http_resp->is_error) {
        $logger->error($http_resp->status_line);
        exit;
    }

    $logger->debug("Extracting body from VM response");
    
    my $http_body = $json_obj->decode($http_resp->content);
    if ($@ || !defined($http_body)) {
        $logger->error("Failed to retrieve SID from VM.".$http_resp->content);
        exit;        
    }

    if (!defined($http_body->{SID})) {
        $logger->info("No SID in VM response");
        exit;        
    }
    
    $logger->debug("VM SID: ".$http_body->{SID});

    return $http_body->{SID};
}

