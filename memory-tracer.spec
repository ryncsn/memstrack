# vim: syntax=spec
Name:           {{{ git_dir_name }}}
Version:        {{{ git_dir_version }}}
Release:        1%{?dist}
Summary:        A memory allocation trace, like a hot spot analyzer for memory allocation
Group:          Applications/System
License:        GPL3
URL:            https://github.com/ryncsn/memory-tracer.git
VCS:            {{{ git_dir_vcs }}}
BuildRequires:  gcc
BuildArch:      x86_64 aarch64

Source:         {{{ git_dir_pack }}}

%description
A memory allocation trace, like a hot spot analyzer for memory allocation

%prep
{{{ git_dir_setup_macro }}}

%build
make

%install
mkdir -p %{buildroot}/%{_bindir}
install -p -m 755 memory-tracer %{buildroot}/%{_bindir}

%files
%{_bindir}/memory-tracer

%changelog
{{{ git_dir_changelog }}}
