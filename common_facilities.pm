package common_facilities;
use strict;
# use warnings;
#use Sys::Syslog qw( :DEFAULT setlogsock);
use LWP::UserAgent;
use JSON;
use Data::Dumper;
use Log::Log4perl;
Log::Log4perl->init("/usr/local/rtp_analyser/log.conf");

use vars qw($logger %CONFIG_PARAM $tshark_ob_filter);
            
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw($logger %CONFIG_PARAM $tshark_ob_filter);

load_config();

$logger = Log::Log4perl->get_logger("RTP_ANALYSER");

sub load_config
{
	unless(%CONFIG_PARAM)
	{
		open(CONFIG, "</usr/local/rtp_analyser/tool.conf") or die "Can't read config: $!";
		while (<CONFIG>) 
		{
			  chomp;                  # no newline
			  s/#.*//;                # no comments
			  s/^\s+//;               # no leading white
			  s/\s+$//;               # no trailing white
			  next unless length;     # anything left?
			  my ($var, $value) = split(/\s*=\s*/, $_, 2);
              if ($var eq "OB_IPs" ) {
                my @OB_IPs = split(/;/, $value);
                my @tshark_exp;
                foreach my $ob_ip (@OB_IPs) {
                    push(@tshark_exp, "\\(ip.src==$ob_ip\\)");
                    $tshark_ob_filter = join("\\|\\|",@tshark_exp);
                }
              }

              $CONFIG_PARAM{$var} = $value;
		}
		close CONFIG;
	}
	
	return 1;
}

1;