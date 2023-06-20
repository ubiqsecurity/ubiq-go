QUIET	:= @

test:
	$(QUIET)go test -count=1

testv:
	$(QUIET)go test -v -count=1

doc:
	$(QUIET)go doc

docv:
	$(QUIET)go doc -all
