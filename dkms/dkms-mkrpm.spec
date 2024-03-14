%{?!module_name: %{error: You did not specify a module name (%%module_name)}}
%{?!version: %{error: You did not specify a module version (%%version)}}
%{?!kernel_versions: %{error: You did not specify kernel versions (%%kernel_version)}}
%{?!packager: %define packager Cambricon <service@cambricon.com>}
%{?!license: %define license Unknown}
%{?!_dkmsdir: %define _dkmsdir /var/lib/dkms}
%{?!_srcdir: %define _srcdir %_prefix/src}
%{?!_datarootdir: %define _datarootdir %{_datadir}}

Summary:	%{module_name} %{version}
Name:		%{module_name}
Version:	%{version}
License:	GPL
Release:	RELEASE_VERSION
BuildArch:	PLATFORM
Group:		System/Kernel
Requires: 	dkms >= 1.95
Requires: 	gcc >= 4.8.5
Requires: 	pciutils make gcc kernel kernel-devel kernel-headers
BuildRequires: 	dkms make gcc kernel kernel-devel kernel-headers rpm-build
Conflicts:      dpkg
Vendor:		Cambricon
URL:		http://www.cambricon.com
BuildRoot: 	%{_tmppath}/%{name}-%{version}-%{release}-root/

%description
The Cambricon %{module_name} %{version}.

%prep
if [ "%mktarball_line" != "none" ]; then
    /usr/sbin/dkms mktarball -m %module_name -v %version %mktarball_line --archive `basename %{module_name}-%{version}.dkms.tar.gz`
    cp -af %{_dkmsdir}/%{module_name}/%{version}/tarball/`basename %{module_name}-%{version}.dkms.tar.gz` %{module_name}-%{version}.dkms.tar.gz
fi
echo 'omit_drivers+=" cambricon-drv "' > /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf
echo 'KERNEL=="cambricon_dev*", MODE="0666"' > /etc/udev/rules.d/99-cambricon-drv.rules
echo 'KERNEL=="cambricon_ipcm*", MODE="0666"' >> /etc/udev/rules.d/99-cambricon-drv.rules
echo 'KERNEL=="cambricon-caps/cap*", MODE="0666"' >> /etc/udev/rules.d/99-cambricon-drv.rules

if [ -f /usr/bin/cnmon ]; then
    rm -f /usr/bin/cnmon
fi

if [ -d /usr/bin/cnmon ]; then
    rm -rf /usr/bin/cnmon
fi

if [ -e /usr/bin/cambricon-bug-report.sh ]; then
    rm -rf /usr/bin/cambricon-bug-report.sh
fi

if [ -e /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh ]; then
    rm -rf /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh
fi

%install
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi
mkdir -p $RPM_BUILD_ROOT/%{_srcdir}
mkdir -p $RPM_BUILD_ROOT/%{_datarootdir}/%{module_name}

if [ -d %{_sourcedir}/%{module_name}-%{version} ]; then
    cp -Lpr %{_sourcedir}/%{module_name}-%{version} $RPM_BUILD_ROOT/%{_srcdir}
fi

if [ -f %{module_name}-%{version}.dkms.tar.gz ]; then
    install -m 644 %{module_name}-%{version}.dkms.tar.gz $RPM_BUILD_ROOT/%{_datarootdir}/%{module_name}
fi

if [ -f %{_sourcedir}/common.postinst ]; then
    install -m 755 %{_sourcedir}/common.postinst $RPM_BUILD_ROOT/%{_datarootdir}/%{module_name}/postinst
fi

%clean
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi
if [ -f /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf ]; then
	rm -f /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf
fi
if [ -f /etc/udev/rules.d/99-cambricon-drv.rules ]; then
	rm -f /etc/udev/rules.d/99-cambricon-drv.rules
fi
if [ -d /etc/udev/script/cambricon ]; then
	rm -rf /etc/udev/script/cambricon
fi

%post
if [ -f /usr/bin/cnmon ]; then
    rm -f /usr/bin/cnmon
fi

if [ -d /usr/bin/cnmon ]; then
    rm -rf /usr/bin/cnmon
fi

if [ -f "/usr/src/%{module_name}-%{version}/cnmon" ];then
    cp /usr/src/%{module_name}-%{version}/cnmon  /usr/bin
fi

if [ -e /usr/bin/cambricon-bug-report.sh ]; then
    rm -rf /usr/bin/cambricon-bug-report.sh
fi

if [ -f "/usr/src/%{module_name}-%{version}/tools/cambricon-bug-report.sh" ];then
    cp /usr/src/%{module_name}-%{version}/tools/cambricon-bug-report.sh  /usr/bin
    chmod 777 /usr/bin/cambricon-bug-report.sh
fi

if [ -e /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh ]; then
    rm -rf /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh
fi
if [ -e /lib/systemd/system-sleep/cambricon_mlu_sleep.sh ]; then
    rm -rf /lib/systemd/system-sleep/cambricon_mlu_sleep.sh
fi
if [ -f "/usr/src/%{module_name}-%{version}/tools/cambricon_mlu_sleep.sh" ];then
    if [ -d "/usr/lib/systemd/system-sleep" ]; then
        cp /usr/src/%{module_name}-%{version}/tools/cambricon_mlu_sleep.sh  /usr/lib/systemd/system-sleep/
        chmod 777 /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh
    elif [ -d "/lib/systemd/system-sleep" ]; then
        cp /usr/src/%{module_name}-%{version}/tools/cambricon_mlu_sleep.sh  /lib/systemd/system-sleep/
        chmod 777 /lib/systemd/system-sleep/cambricon_mlu_sleep.sh
    fi
fi


echo "cambricon-drv" > /etc/modules-load.d/cambricon-drv.conf

echo 'omit_drivers+=" cambricon-drv "' > /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf
echo 'KERNEL=="cambricon_dev*", MODE="0666"' > /etc/udev/rules.d/99-cambricon-drv.rules
echo 'KERNEL=="cambricon_ipcm*", MODE="0666"' >> /etc/udev/rules.d/99-cambricon-drv.rules
echo 'KERNEL=="cambricon-caps/cap*", MODE="0666"' >> /etc/udev/rules.d/99-cambricon-drv.rules

for POSTINST in %{_prefix}/lib/dkms/common.postinst %{_datarootdir}/%{module_name}/postinst; do
    if [ -f $POSTINST ]; then
        $POSTINST %{module_name} %{version} %{_datarootdir}/%{module_name}
        if [ "$MLU_RUNMODE" == "PF" ]; then
            echo -e "Install cambricon Virt $MLU_RUNMODE driver into system!"
            cat /usr/src/%{module_name}-%{version}/dkms/cambricon-drv.conf > /etc/modprobe.d/cambricon-drv.conf
            echo "options cambricon-drv sriov_en=1" >> /etc/modprobe.d/cambricon-drv.conf
        else
            cat /usr/src/%{module_name}-%{version}/dkms/cambricon-drv.conf > /etc/modprobe.d/cambricon-drv.conf
        fi
        dkms status -m %{module_name} -v %{version} | grep installed
        if [ $? -eq 0 ]; then
            lsmod | grep "cambricon"
            if [ $? -eq 0 ]; then
                echo "---------------------------------------------------------------"
                echo "Driver installation is successful, it is recommended to restart"
                echo "the machine to ensure that the driver works normally."
                echo "---------------------------------------------------------------"
            else
                echo "--------------------------------------------------------------------"
                echo "Driver installation is successful, but cambricon module load failed."
                echo "Please check your permission, system setting and dmesg log for more"
                echo "information."
                echo "--------------------------------------------------------------------"
            fi
            exit 0
        else
            echo "---------------------------------------------------------------------"
            echo "Driver installation is failed. Please make sure using the appropriate"
            echo "operating system version. See the Cambricon_Driver_User_guide.pdf"
            echo "for more information."
            echo "---------------------------------------------------------------------"
            exit 1
        fi
    fi
    echo "WARNING: $POSTINST does not exist."
done

echo -e "ERROR: DKMS version is too old and %{module_name} was not"
echo -e "built with legacy DKMS support."
echo -e "You must either rebuild %{module_name} with legacy postinst"
echo -e "support or upgrade DKMS to a more current version."
exit 1

%preun
echo -e
echo -e "Uninstall of %{module_name} module (version %{version}) beginning:"
cp -rdpf /usr/src/%{module_name}-%{version}/unload_auto /usr/bin/unload_auto
dkms_status=`dkms status -m %{module_name} -v %{version}`
if [ `echo %{dkms_status} | grep -c ": added"` -eq 1 ]; then
	dkms remove -m %{module_name} -v %{version} --all --rpm_safe_upgrade
fi
if [ -e "/var/lib/dkms/%{module_name}/%{version}" ]; then
	echo "Removing old %{module_name}-%{version} DKMS files..."
	dkms remove -m %{module_name} -v %{version} --all
fi
exit 0

%postun
if [ $1 == 0 ];then
    echo "--------------------uninstall--------------------"
    /usr/bin/unload_auto dkms_rpm
    rm -rf /usr/bin/unload_auto
    if [ -f /usr/bin/cnmon ]; then
        rm -f /usr/bin/cnmon
    fi
    if [ -d /usr/bin/cnmon ]; then
        rm -rf /usr/bin/cnmon
    fi
    if [ -e /usr/bin/cambricon-bug-report.sh ]; then
        rm -rf /usr/bin/cambricon-bug-report.sh
    fi
    if [ -e /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh ]; then
        rm -rf /usr/lib/systemd/system-sleep/cambricon_mlu_sleep.sh
    fi
    if [ -e /lib/systemd/system-sleep/cambricon_mlu_sleep.sh ]; then
        rm -rf /lib/systemd/system-sleep/cambricon_mlu_sleep.sh
    fi
    if [ -f /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf ]; then
	rm -f /usr/lib/dracut/dracut.conf.d/90-mlu200-dracut.conf
    fi
    if [ -f /etc/udev/rules.d/99-cambricon-drv.rules ]; then
	rm -f /etc/udev/rules.d/99-cambricon-drv.rules
    fi
    if [ -d /etc/udev/script/cambricon ]; then
	rm -rf /etc/udev/script/cambricon
    fi
    if [ -f /etc/modprobe.d/cambricon-drv.conf ]; then
	rm -f /etc/modprobe.d/cambricon-drv.conf
    fi
    if [ -f /etc/modules-load.d/cambricon-drv.conf ]; then
	rm -f /etc/modules-load.d/cambricon-drv.conf
    fi
elif [ $1 == 1 ];then
    echo "--------------------install--------------------"
    rm -rf /usr/bin/unload_auto
elif [ $1 == 2 ];then
    echo "--------------------update--------------------"
    rm -rf /usr/bin/unload_auto
fi

find /lib/modules -name "cambricon-gdr*" | grep weak-updates | xargs rm -f
find /lib/modules -name "cambricon-drv*" | grep weak-updates | xargs rm -f
find /lib/modules -name "cambricon-peermem*" | grep weak-updates | xargs rm -f

if [ -d /usr/src/%{module_name}-%{version} ]; then
	find /usr/src/%{module_name}-%{version} -name "*.ko*" -delete
	rm -fr /usr/src/%{module_name}-%{version}
fi
exit 0

%files
%defattr(-,root,root)
%{_srcdir}
%{_datarootdir}/%{module_name}/

%changelog
* Wed May 22 2019 Zhouguojian <zhouguojian@cambricon.com>
- release cambricon_driver vPKG_VERSION-RELEASE_VERSION
