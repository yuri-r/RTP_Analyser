#!/bin/bash


####################################################################################################

copy_files()
{
    cd $install_dir
     
    unix_time=`date +%s`
       
    #copy aaa-api files
    if [[ ! -e /usr/local/rtp_analyser ]]; then
        mkdir -p /usr/local/rtp_analyser
    else 
        rm -rf /usr/local/rtp_analyser/*
    fi

    mkdir -p /usr/local/rtp_analyser/pcaps

    cp -r ./* /usr/local/rtp_analyser/
#    cp ./etc/init.d/rtp_analyser /etc/init.d/
    
    chmod +x /usr/local/rtp_analyser/rtp_analyser.pl
#    chmod +x /etc/init.d/rtp_analyser
    
    #create log folder
    if [[ ! -e /var/log/rtp_analyser ]]; then
        mkdir /var/log/rtp_analyser
    fi
    
    rc=`getent passwd | grep -c '^rtp_analyser:'`
	if [[ $rc == 0 ]] ; then
        useradd -r -s /bin/bash rtp_analyser
	fi

    chown -R rtp_analyser:rtp_analyser /usr/local/rtp_analyser
    chown -R rtp_analyser:rtp_analyser /var/log/rtp_analyser
}

install_libraries()
{
    echo "Installing DateTime lib..."    

    if [[ $version ]] ; then
        #update repository and system
        if [[ -e /etc/yum.repos.d/opensips.repo ]]; then
            rm -f /etc/yum.repos.d/opensips.repo
        fi
        
        yum -y install perl-DateTime &
    else
        apt-get -y install libdatetime-perl &
    fi

    wait $!
	rc=$?
	if [[ $rc != 0 ]] ; then
		echo "Install DateTime failed!!!"
		return $rc
	fi
    
    ################
    echo "Installing LibWWW lib..."    

    if [[ $version ]] ; then
        yum -y install perl-libwww-perl &
    else
        apt-get -y install libwww-perl &
    fi

    wait $!
	rc=$?
	if [[ $rc != 0 ]] ; then
		echo "Install LibWWW failed!!!"
		return $rc
	fi
    
    ################
    echo "Installing Proc-Daemon lib..."    

    if [[ $version ]] ; then
        yum -y install perl-Proc-Daemon &
    else
        apt-get -y install libproc-daemon-perl &
    fi

    wait $!
	rc=$?
	if [[ $rc != 0 ]] ; then
		echo "Install Proc-Daemon failed!!!"
		return $rc
	fi

    wait $!
	rc=$?
	if [[ $rc != 0 ]] ; then
		echo "Install Proc-Daemon failed!!!"
		return $rc
	fi

    ################
    echo "Installing Log4Perl lib..."    

    if [[ $version ]] ; then
        yum -y install perl-Log-Log4perl &
    else
        apt-get -y install liblog-log4perl-perl &
    fi

    wait $!
	rc=$?
	if [[ $rc != 0 ]] ; then
		echo "Install Log4Perl failed!!!"
		return $rc
	fi
    
    ################
    echo "Installing Encode-Locale lib..."    

    if [[ $version ]] ; then
        yum -y install perl-Encode-Locale &
        wait $!
        rc=$?
        if [[ $rc != 0 ]] ; then
            echo "Install Encode-Locale failed!!!"
            return $rc
        fi
    fi

    ################
    echo "Installing perl-JSON lib..."    

    if [[ $version ]] ; then
        yum -y install perl-JSON &
        wait $!
        rc=$?
        if [[ $rc != 0 ]] ; then
            echo "Install perl-JSON failed!!!"
            return $rc
        fi
    fi
}

####################################################################################################

#installation process:
echo "INFO: The RTP analyser installation in process..."
version=`cat /etc/issue | grep CentOS`
install_dir=`pwd`  

#/etc/init.d/rtp_analyser stop &
#wait $!

echo "INFO: Enabling EPEL repository ..."

sed -i.back 's/.*enabled=.*/enabled=1/1' /etc/yum.repos.d/epel.repo


echo "INFO: Installing libraries ..."
install_libraries
wait $!
rc=$?
if [[ $rc != 0 ]] ; then
    echo "FATAL: The RTP analyser installation has been failed"
    exit
fi

echo "INFO: Copying files ..."
copy_files

#/etc/init.d/rtp_analyser start &
#wait $!
#rc=$?
#if [[ $rc != 0 ]] ; then
#    echo "The RTP analyser failed to start!!!"
#    echo "FATAL: The The RTP analyser installation has been failed"
#    exit
#fi

echo "INFO: The The RTP analyser installation has been completed"
exit
