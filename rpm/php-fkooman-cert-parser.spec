%global composer_vendor  fkooman
%global composer_project cert-parser

%global github_owner     fkooman
%global github_name      php-cert-parser

Name:       php-%{composer_vendor}-%{composer_project}
Version:    1.0.0
Release:    1%{?dist}
Summary:    Simple OpenSSL based X.509 certificate parser

Group:      System Environment/Libraries
License:    ASL 2.0
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
BuildArch:  noarch

Provides:   php-composer(%{composer_vendor}/%{composer_project}) = %{version}

Requires:   php(language) >= 5.3.3
Requires:   php-hash
Requires:   php-openssl
Requires:   php-pcre
Requires:   php-spl

%description
This library enables you to parse X.509 certificates in order to be able to 
extract some attributes from it.

%prep
%setup -qn %{github_name}-%{version}

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/php
cp -pr src/* ${RPM_BUILD_ROOT}%{_datadir}/php

%files
%defattr(-,root,root,-)
%dir %{_datadir}/php/%{composer_vendor}/X509
%{_datadir}/php/%{composer_vendor}/X509/*
%doc README.md CHANGES.md composer.json
%license COPYING

%changelog
* Wed Jul 08 2015 François Kooman <fkooman@tuxed.net> - 1.0.0-1
- update to 1.0.0

* Fri Jun 26 2015 François Kooman <fkooman@tuxed.net> - 0.2.0-1
- update to 0.2.0

* Mon Jan 26 2015 François Kooman <fkooman@tuxed.net> - 0.1.8-1
- update to 0.1.8
