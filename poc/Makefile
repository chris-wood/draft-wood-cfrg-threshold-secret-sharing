TESTVECTORS := "TSS-F64.json" "TSS-F128.json" "TSS-F255.json" "DVTSS-Ristretto255.json" "RVTSS-Ristretto255.json"
FORMATTEDVECTORS := "test-vectors.txt"
SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

test: pyfiles
	@sage tss.sage
	@sage dvtss.sage
	@sage rvtss.sage

vectors: test 
	@python3 format_test_vectors.py $(TESTVECTORS) > $(FORMATTEDVECTORS)

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__ $(TESTVECTORS) $(FORMATTEDVECTORS)