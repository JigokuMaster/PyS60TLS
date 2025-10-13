
MBEDTLS_PATH = $(shell realpath ~/Dev/C/mbedtls-3.4.1)
PYTHON_PATH= $(shell realpath ~/Dev/C/Python-2.2.2)
LINUX_EXT_PATH = /tmp/tls.so

CXXFLAGS += -fPIC -w -I$(PYTHON_PATH) \
	      -I$(PYTHON_PATH)/Include \
	      -I$(MBEDTLS_PATH)/include \

LD_FLAGS += -shared -L$(MBEDTLS_PATH)/library \
	    -lmbedtls -lmbedx509 -lmbedcrypto \
	    -L$(PYTHON_PATH) -lpython2.2

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
	abld reallyclean gcce urel


