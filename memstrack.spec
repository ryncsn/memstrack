# vim: syntax=spec
Name:           {{{ git_dir_name }}}
Version:        {{{ git_dir_version }}}
Release:        1%{?dist}
Summary:        A memory allocation trace, like a hot spot analyzer for memory allocation
Group:          Applications/System
License:        GPL3
URL:            https://github.com/ryncsn/memstrack.git
VCS:            {{{ git_dir_vcs }}}
BuildRequires:  gcc
BuildArch:      x86_64 aarch64

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
%define dracutlibdir %{_prefix}/lib/dracut
mkdir -p %{buildroot}/%{dracutlibdir}/modules.d/99memstrack/
install -p -m 644 misc/99memstrack/module-setup.sh %{buildroot}/%{dracutlibdir}/modules.d/99memstrack/module-setup.sh
install -p -m 755 misc/99memstrack/start-tracing.sh %{buildroot}/%{dracutlibdir}/modules.d/99memstrack/start-tracing.sh
install -p -m 755 misc/99memstrack/stop-tracing.sh %{buildroot}/%{dracutlibdir}/modules.d/99memstrack/stop-tracing.sh

%files
%{_bindir}/memstrack
%files dracut-memstrack
%{dracutlibdir}/modules.d/99memstrack/module-setup.sh
%{dracutlibdir}/modules.d/99memstrack/start-tracing.sh
%{dracutlibdir}/modules.d/99memstrack/stop-tracing.sh
%doc

%changelog
{{{ git_dir_changelog }}}
