


.PHONY: clean all test


all:
	$(MAKE) -C Debug all

clean:
	$(MAKE) -C Debug clean

test:
	rm -f logs/*
	./Debug/dlltagentUnitTest --gtest_filter=*fast
	./Debug/dlltagentUnitTest --gtest_filter=*long

