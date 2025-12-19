%global debug_package %{nil}
Name: flow
Version: 1.0.0
Release: 1%{?dist}
Summary: Flow Network Monitor
License: None
URL: https://www.github.com/abisinraj/flow
Source0: %{name}-%{version}.tar.gz
Group: System/Monitoring
BuildRequires: python3, python3-pip, python3-devel
Requires: libcap, nftables, systemd
BuildArch: x86_64

%description
Flow is a local network monitor and lightweight host defense UI.

%prep
%autosetup -n %{name}-%{version} || :

%build
# Install dependencies and build PyInstaller binary
pip3 install --user -r requirements.txt
pip3 install --user pyinstaller
python3 -m PyInstaller flow.spec

%install
rm -rf %{buildroot}

# Install the frozen binary
mkdir -p %{buildroot}%{_bindir}
install -m 0755 dist/flow %{buildroot}%{_bindir}/flow

# Install desktop file
mkdir -p %{buildroot}/usr/share/applications
install -m 0644 packaging/flow.desktop %{buildroot}/usr/share/applications/flow.desktop

# Install firewall helper
mkdir -p %{buildroot}/opt/flow-helper
install -m 0644 core/firewall_helper.py %{buildroot}/opt/flow-helper/firewall_helper.py
install -m 0755 packaging/flow-firewall-helper %{buildroot}%{_bindir}/flow-firewall-helper

# Install systemd service for firewall helper
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 packaging/flow-firewall.service %{buildroot}%{_unitdir}/flow-firewall.service

# Install optional user mode service (for future use)
mkdir -p %{buildroot}/opt/flow/packaging
install -m 0644 packaging/flow.service %{buildroot}/opt/flow/packaging/flow.service

%files
%defattr(-,root,root,-)
%{_bindir}/flow
%{_bindir}/flow-firewall-helper
/usr/share/applications/flow.desktop
%{_unitdir}/flow-firewall.service
%dir /opt/flow-helper
/opt/flow-helper/firewall_helper.py
%dir /opt/flow/packaging
/opt/flow/packaging/flow.service

%post
# Create flow group if it doesn't exist
getent group flow >/dev/null || groupadd -r flow

# Apply Linux capabilities to Flow UI binary (not helper - it runs as root)
if [ -x /usr/sbin/setcap ]; then
    /usr/sbin/setcap cap_net_raw,cap_net_admin+ep %{_bindir}/flow || :
    echo "Flow capabilities applied: cap_net_raw,cap_net_admin"
else
    echo "Warning: setcap not found. Flow will require sudo to run."
    echo "Install libcap package and run: sudo setcap cap_net_raw,cap_net_admin+ep %{_bindir}/flow"
fi

# Enable and start firewall helper service
if [ $1 -eq 1 ]; then
    # First install
    systemctl daemon-reload || :
    systemctl enable flow-firewall.service || :
    systemctl start flow-firewall.service || :
    echo "Flow firewall helper service started"
    echo ""
    echo "IMPORTANT: Add users to the 'flow' group to allow them to use Flow:"
    echo "  sudo usermod -aG flow <username>"
    echo "  (User must log out and back in for group changes to take effect)"
fi

%preun
# Stop and disable firewall helper on uninstall
if [ $1 -eq 0 ]; then
    systemctl stop flow-firewall.service || :
    systemctl disable flow-firewall.service || :
    systemctl daemon-reload || :
    # Note: We don't delete the flow group in case other packages use it
fi

%changelog
* Thu Dec 11 2025 ABISIN RAJ <abisinraj04@gmail.com> - 1.0.0-1
- Initial packaging
