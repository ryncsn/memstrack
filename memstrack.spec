# vim: syntax=spec
Name:           {{{ git_dir_name }}}
Version:        {{{ git_dir_version }}}
Release:        1%{?dist}
Summary:        A memory allocation tracer, like a hot spot analyzer for memory allocation
License:        GPLv3
URL:            https://github.com/ryncsn/memstrack
VCS:            {{{ git_dir_vcs }}}
BuildRequires:  gcc
BuildRequires:  ncurses-devel

Source:         {{{ git_dir_pack }}}

%description
A memory allocation tracer, like a hot spot analyzer for memory allocation

%package dracut
Summary: Debug hook for analyzing memory with memstract in dracut
Requires: %{name} = %{version}-%{release}
Requires: dracut
BuildArch: noarch

%description dracut
Debug hook for analyzing memory with memstract in dracut, help analyze
booting stage memory usage.

%prep
{{{ git_dir_setup_macro }}}

%build
%{set_build_flags}
%make_build

%install
# memstrack binary
mkdir -p %{buildroot}/%{_bindir}
install -p -m 755 memstrack %{buildroot}/%{_bindir}

# dracut module part
# keep dracutlibdir consistent with the definition in dracut.spec
%define dracutlibdir %{_prefix}/lib/dracut
%define dracutmoduledir %{dracutlibdir}/modules.d/99memstrack
mkdir -p %{buildroot}/%{dracutmoduledir}

install -p -m 644 misc/99memstrack/memstrack.service %{buildroot}/%{dracutmoduledir}/memstrack.service
install -p -m 755 misc/99memstrack/module-setup.sh %{buildroot}/%{dracutmoduledir}/module-setup.sh
install -p -m 755 misc/99memstrack/memstrack-start.sh %{buildroot}/%{dracutmoduledir}/memstrack-start.sh
install -p -m 755 misc/99memstrack/memstrack-report.sh %{buildroot}/%{dracutmoduledir}/memstrack-report.sh

%files
%doc README.md
%license LICENSE
%{_bindir}/memstrack

%files dracut
%dir %{dracutmoduledir}
%{dracutmoduledir}/memstrack.service
%{dracutmoduledir}/module-setup.sh
%{dracutmoduledir}/memstrack-start.sh
%{dracutmoduledir}/memstrack-report.sh

%changelog
{{{ git_dir_changelog }}}
