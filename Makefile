FILES_TO_RPM = src mon tools wopiserver.conf wopiserver.service wopiserver.logrotate
SPECFILE = $(shell find . -type f -name *.spec)
VERSREL  = $(shell ./getbuildversion.sh)
VERSION  = $(shell echo ${VERSREL} | cut -d\- -f 1)
PACKAGE  = $(shell awk '$$1 == "Name:"     { print $$2 }' $(SPECFILE) )
RELEASE  = $(shell awk '$$1 == "Release:"  { print $$2 }' $(SPECFILE) )
rpmbuild = ${shell pwd}/rpmbuild

# ------------------------------------------

clean:
	@rm -rf $(PACKAGE)-$(VERSION)
	@rm -rf $(rpmbuild)
	@find . -name '*.pyc' -exec rm -f \{\} \;
	@find . -name '*.pyo' -exec rm -f \{\} \;

rpmdefines=--define='_topdir ${rpmbuild}' \
	--define='_sourcedir %{_topdir}/SOURCES' \
	--define='_builddir %{_topdir}/BUILD' \
	--define='_srcrpmdir %{_topdir}/SRPMS' \
	--define='_rpmdir %{_topdir}/RPMS' \
	--define='_version $(VERSION)'

dist: clean
	@mkdir -p $(PACKAGE)-$(VERSION)
	@cp -r $(FILES_TO_RPM) $(PACKAGE)-$(VERSION)
	tar cpfz ./$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION)

prepare: dist
	@mkdir -p $(rpmbuild)/RPMS/noarch
	@mkdir -p $(rpmbuild)/SRPMS/
	@mkdir -p $(rpmbuild)/SPECS/
	@mkdir -p $(rpmbuild)/SOURCES/
	@mkdir -p $(rpmbuild)/BUILD/
	@mv $(PACKAGE)-$(VERSION).tar.gz $(rpmbuild)/SOURCES 
	@cp $(SPECFILE) $(rpmbuild)/SOURCES 

srpm: prepare $(SPECFILE)
	rpmbuild --nodeps -bs $(rpmdefines) $(SPECFILE)
	#cp $(rpmbuild)/SRPMS/* .

rpm: srpm
	rpmbuild --nodeps -bb $(rpmdefines) $(SPECFILE)
	cp $(rpmbuild)/RPMS/noarch/* .

docker: clean
	sudo docker-compose -f wopiserver.yaml build --build-arg VERSION=$(VERSREL) wopiserver
