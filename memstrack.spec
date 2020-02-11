# vim: syntax=spec
Name:           {{{ git_dir_name }}}
Version:        {{{ git_dir_version }}}
Release:        1%{?dist}
Summary:        A memory allocation trace, like a hot spot analyzer for memory allocation
Group:          Applications/System
License:        GPLv3
URL:            https://github.com/ryncsn/memstrack
VCS:            {{{ git_dir_vcs }}}
BuildRequires:  gcc ncurses-devel

Source:         {{{ git_dir_pack }}}

%description
A memory allocation trace, like a hot spot analyzer for memory allocation

%package dracut-memstrack
Summary: Memory debug hooks with dracut
Requires: dracut
BuildArch: noarch
%description dracut-memstrack
Memory debug hooks with dracut

%prep
{{{ git_dir_setup_macro }}}

%build
make

%install
# memstrack binary
mkdir -p %{buildroot}/%{_bindir}
install -p -m 755 memstrack %{buildroot}/%{_bindir}

# dracut module part
%define dracutlibdir %{_libdir}/dracut
%define dracutmoduledir %{dracutlibdir}/module.d/99memstrack
mkdir -p %{buildroot}/%{dracutmoduledir}

install -p -m 644 misc/99memstrack/module-setup.sh %{buildroot}/%{dracutmoduledir}/module-setup.sh
install -p -m 755 misc/99memstrack/start-tracing.sh %{buildroot}/%{dracutmoduledir}/start-tracing.sh
install -p -m 755 misc/99memstrack/stop-tracing.sh %{buildroot}/%{dracutmoduledir}/stop-tracing.sh

%files
%{_bindir}/memstrack
%files dracut-memstrack
%{dracutmoduledir}/module-setup.sh
%{dracutmoduledir}/start-tracing.sh
%{dracutmoduledir}/stop-tracing.sh
%doc

%changelog
{{{ git_dir_changelog }}}
