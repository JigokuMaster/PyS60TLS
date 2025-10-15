
MBEDTLS_PATH = $(shell realpath ~/Dev/C/mbedtls-3.4.1)
LINUX_EXT_PATH = /tmp/tls.so

CXXFLAGS += -fPIC -w -I$(PYTHON_PATH) \
	      -I$(PYTHON_PATH)/Include \
	      -I$(MBEDTLS_PATH)/include \

LD_FLAGS += -shared -L$(MBEDTLS_PATH)/library \
	    -lmbedtls -lmbedx509 -lmbedcrypto \
	    -L$(PYTHON_PATH) $(PYTHON_LIB)

CXXSRCS = $(shell ls *.cpp)
CXX_OBJS = $(patsubst %.cpp,%.o,$(CXXSRCS))

$(CXX_OBJS): %.o : %.cpp
	$(CXX) -c $(CXXFLAGS) -o $@ $<

linux_ext: $(CXX_OBJS)
	$(CXX) -o $(LINUX_EXT_PATH) $< $(LD_FLAGS)

pys60_ext:
	bldmake bldfiles gcce urel
	abld build -v gcce urel

linux_test: 
	$(PYTHON_PATH)/python tests.py
clean: 
	rm -rf *.o $(LINUX_EXT_PATH)
	find . -type f -name '*.pyc' -exec rm {} +
	abld reallyclean gcce urel

REL_DIST = /tmp/PyS60TLS
BIN_DIST = $(REL_DIST)/Sys/Bin
BIN_SRC = $(EPOCROOT)/epoc32/release/gcce/urel
RES_DIST = $(REL_DIST)/Resource
DIST_FILE = PyS60TLS.zip

pys60_rel: 
	find . -type f -name '*.pyc' -exec rm {} +
	rm -rf $(REL_DIST)
	rm -f $(DIST_FILE) 
	mkdir -p $(BIN_DIST)
	mkdir -p $(RES_DIST)/Python25
	cp -v $(BIN_SRC)/kf_tls.pyd $(BIN_DIST)
	cp -v $(BIN_SRC)/tls.pyd $(BIN_DIST)
	cp -v httpslib.py $(RES_DIST)
	cp -v httpslib.py $(RES_DIST)/Python25
	cp -v -R extra/requests-0.10.0/requests $(RES_DIST)/Python25
	7z a -tzip $(DIST_FILE) $(REL_DIST)

