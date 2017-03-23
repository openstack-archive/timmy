%global with_python3 0
%global with_docs 0

%global pypi_name timmy

Name:           python-%{pypi_name}
Version:        1.26.11
Release:        1%{?dist}~mos0
Summary:        Log collector tool for OpenStack Fuel

License:        ASL 2.0
URL:            https://github.com/adobdin/timmy
Source0:        https://pypi.io/packages/source/t/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python2-devel
BuildRequires:  python-setuptools
Requires:       PyYAML >= 3.11


%description
Mirantis OpenStack Ansible-like tool for parallel node operations: two-way data
transfer, log collection, remote command execution.

%if 0%{?with_docs}
%package doc
Summary:        Documentation for timmy tool
Group:          Documentation
BuildRequires:  python-sphinx


%description      doc
Mirantis OpenStack Ansible-like tool for parallel node operations.
This package contains auto-generated documentation.
%endif


%if 0%{?with_python3}
%package -n python3-%{pypi_name}
Summary:        Log collector tool for OpenStack Fuel
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
Requires:       python3-PyYAML

%description -n python3-%{pypi_name}
Mirantis OpenStack Ansible-like tool for parallel node operations: two-way data
transfer, log collection, remote command execution.
%endif

%prep
%setup -cq -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%if 0%{?with_python3}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif

%build
%{__python2} setup.py build
%if 0%{?with_docs}
# generate html docs
#todo - switch to build_sphinx
#%{__python2} setup.py build_sphinx
export PYTHONPATH="%{python2_sitearch}:%{python2_sitelib}:%{buildroot}%{python2_sitelib}:."
sphinx-build -b html doc/source/ doc/build/
# remove the sphinx-build leftovers
rm -rf html/.{doctrees,buildinfo}
%endif


%install
%{__python2} setup.py install --skip-build --root %{buildroot}
install -d -m 755 %{buildroot}/etc/logrotate.d
install -m 644 logrotate.d/timmy %{buildroot}/etc/logrotate.d/timmy
%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py install --skip-build --root %{buildroot}
popd
%endif


%files
%doc README.md
%{_bindir}/timmy
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name}_data
%{python2_sitelib}/*.egg-info
%config(noreplace,missingok)	/etc/logrotate.d/timmy

%if 0%{?with_docs}
%files doc
%doc doc/build/html
%license LICENSE
%endif

%if 0%{?with_python3}
%files -n python3-%{pypi_name}
%doc README.md
%{_bindir}/timmy
%{python3_sitelib}/%{pypi_name}
%{python3_sitelib}/%{pypi_name}_data
%{python3_sitelib}/*.egg-info
%config(noreplace,missingok)	/etc/logrotate.d/timmy
%endif


%changelog
* Wed Mar 22 2017 Dmitrii Kabanov <dkabanov@mirantis.com> - 1.26.11
- Change: prepend conf.env_vars to scripts with env vars

* Mon Mar 20 2017 Dmitrii Kabanov <dkabanov@mirantis.com> - 1.26.10
- Change: use environment variable for openrc in SPT

* Tue Mar 14 2017 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.9
- Add: collect ceilometer & aodh config
- Fix: add "fuel2 task list" for 10.x series

* Fri Feb 24 2017 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.8
- Fix: exec_pair trace; SPT bugs; print non-0 exit

* Thu Feb 23 2017 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.7
- Fix: UnicodeDecodeError, broken spec; add SPT
- Update documentation to match timmy 1.26.6 code
- Fix: CLI docs

* Thu Jan 19 2017 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.6
- Add yum.repos.d directory to snapshot
- Change: print only summary for analysis module if all nodes are ok
- Replace yaml.load() with yaml.safe_load()
- Change: minor changes in analyze & rabbitmq module
- Added: stderr for mapping scripts

* Tue Dec 27 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.5
- Change: minor changes in analyze & rabbitmq module
- Add: stderr for mapping scripts

* Thu Dec 22 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.4
- Add: max_pairs argument; other minor changes

* Wed Dec 21 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.3
- Fix: scripts_all_pairs sometimes uses same node

* Tue Dec 20 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.26.2
- Add: rabbitmq analysis module

* Tue Dec 20 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.26.1
- Fix: download network templates for 9.1

* Thu Dec 15 2016 Alexander Lemeshko <oliemieshko@mirantis.com> - 1.26.0
- Add: scripts_all_pairs 'one way' mode

* Wed Dec 14 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.25.5
- Fix: RuntimeWarning when using analyze

* Mon Dec 12 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.25.4
- Change: compact analyze output, minor refactor

* Mon Dec 12 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.25.3
- Add: dynamic import of analyze modules

* Thu Dec 9 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.25.2
- Add: fuel network template download script

* Fri Dec 9 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.25.1
- Fix: IOError if no-clean + outdir missing

* Fri Dec 9 2016 Alexander Lemeshko <oliemieshko@mirantis.com> - 1.25.0
- Add: ability to analyze old results

* Wed Dec 7 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.24.2
- Fix: merge postgres dump

* Tue Dec 6 2016 Alexander Lemeshko <oliemieshko@mirantis.com> - 1.24.1
- Fix: fake not implemented for commands

* Tue Dec 6 2016 Alexander Lemeshko <oliemieshko@mirantis.com> - 1.24.0
- Add: function analyze

* Mon Dec 5 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.23.7
- Add: collect haproxy stats

* Wed Nov 30 2016 Dmitry Sutyagin <dstuaygin@mirantis.com> - 1.23.6
- Fix: Fuel not skipped when shell mode used

* Tue Nov 29 2016 Dmitry Sutyagin <dstuyagin@mirantis.com> - 1.23.5
- Change: fuel postgres dump collection
- Add: timmy version in log and outdir
- Change: collect /etc/fuel** instead of /etc/fuel
- Add: debugging traceback on USR1

* Thu Nov 24 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.23.3
- Fix: timmy fails in "mdir" when using --dest-file
- Fix: timmy stuck when calculating log size
- Merge "fix: conf_assign_once can assign to skipped nodes"

* Tue Nov 22 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.23.1
- fix: conf_assign_once can assign to skipped nodes
- Add: collect resolv.conf in Xenial (systemd)
- Add: make rsync options configurable

* Fri Nov 18 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.22.2
- Add: load notice in usage doc
- Fix: issue #65
- Fix: modules not installed
- Add: Timmy modular rewrite
- Add: scripts_all_pairs - new functionality
- Fix: regression - subs don't stop on Ctrl+C
- Fix: main process stuck if subprocess killed
- Fix: revert occasionally disabled get_nodes_api
- Add: sample logrotate configuration
- Fix: make logging honor logrotate, fix getLogger
- Add: scripts_all_pairs - new functionality
- Fix: regression - subs don't stop on Ctrl+C
- Fix: main process stuck if subprocess killed
- Fix: timmy exits 0 on unhandled exceptions
- Add: login parameter for ssh
- Fix: Too many open files

* Thu Sep 22 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.20.4
- Fix: exit properly on not enough space
- Fix: trace when file missing in get_cluster_id
- Change: increase default timeout for commands/scripts to 30
- Add: debug messages with pid
- Fix: logs-maxthreads set to 10; default was too high
- Fix: require pytest-runner only for test command
- Fix: wheel support
- Change: iptables collection, remove iptables from env
- Add: test for path sep in scripts in rq/default.yaml
- Remove: fuelclient support in Fuel 9.1+
- Add: conf collection for ironic and cinder-block-storage
- Fix: fuel CLI auth, fuel CLI for 9.0+

* Thu Sep 15 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.20.3
- Fix: incorrect filelist names in rq

* Tue Sep 13 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.20.1
- Fix: check free space for archive directory

* Thu Sep 08 2016 Dmitry Sutyagin <dsutyagin@mirantis.com> - 1.19.5
- no log exclusions by default, clearer size message
  fix: filter should be an instance

* Wed Sep 07 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.19.3
- Package update

* Tue Sep 06 2016 Dmitry <dsutyagin@mirantis.com> - 1.19.1
- Fix: do not wipe archive_dir to prevent unexpected data deletion

* Tue Aug 23 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.19.0
- Package update

* Tue Aug 23 2016 Aleksandr Dobdin <adobdin@mirantis.com> - 1.16.2-1
- Version bump

* Tue Aug 2 2016 Igor Yozhikov <iyozhikov@mirantis.com> - 1.14.3-1
- Initial package
