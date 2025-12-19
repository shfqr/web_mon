Name:           webmon
Version:        0.1.3
Release:        1%{?dist}
Summary:        Lightweight web system monitor
License:        Custom
URL:            https://example.invalid/webmon
Source0:        webmon-%{version}.tar.gz
BuildRequires:  gcc, make
Requires:       /sbin/ldconfig

%description
Minimal web-based system monitor with JSON endpoint and responsive UI.

%prep
%setup -q

%build
make CC=%{__cc} CFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} PREFIX=%{_prefix}
install -Dm0644 packaging/systemd/webmon.service %{buildroot}%{_unitdir}/webmon.service

%check
%{buildroot}%{_bindir}/webmon -h >/dev/null 2>&1 || true

%files
%doc README.md
%{_bindir}/webmon
%{_unitdir}/webmon.service

%changelog
* Wed Jan 01 2025 webmon Maintainers <ops@example.com> - 0.1.3-1
- Initial package skeleton
