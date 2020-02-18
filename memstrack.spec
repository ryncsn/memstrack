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
Requires: dracut
BuildArch: noarch

%description dracut
Debug hook for analyzing memory with memstract in dracut, help analyze
booting stage memory usage.

%prep
{{{ git_dir_setup_macro }}}

%build
%{set_build_flags}
make

%install
# memstrack binary
mkdir -p %{buildroot}/%{_bindir}
install -p -m 755 memstrack %{buildroot}/%{_bindir}

# dracut module part
# keep dracutlibdir consistent with the definition in dracut.spec
%define dracutlibdir %{_prefix}/lib/dracut
%define dracutmoduledir %{dracutlibdir}/module.d/99memstrack
mkdir -p %{buildroot}/%{dracutmoduledir}

install -p -m 644 misc/99memstrack/module-setup.sh %{buildroot}/%{dracutmoduledir}/module-setup.sh
install -p -m 755 misc/99memstrack/start-tracing.sh %{buildroot}/%{dracutmoduledir}/start-tracing.sh
install -p -m 755 misc/99memstrack/stop-tracing.sh %{buildroot}/%{dracutmoduledir}/stop-tracing.sh

%files
%{_bindir}/memstrack
%license LICENSE

%files dracut
%dir %{dracutmoduledir}
%{dracutmoduledir}/module-setup.sh
%{dracutmoduledir}/start-tracing.sh
%{dracutmoduledir}/stop-tracing.sh
%license LICENSE

%changelog
{{{ git_dir_changelog }}}
