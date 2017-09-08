# Project structure
SRCDIR:=src
BUILDDIR:=build
BINDIR:=bin

# Compiler config
CXX:=g++
CPPFLAGS:=-Wall -pthread -O2
CXXFLAGS:=-std=c++11
LDFLAGS:=-O2 -pthread

# Paths
SRCEXT:=cpp
ALLFILES:=$(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
DEPS:=$(filter-out %.main.$(SRCEXT), $(ALLFILES))
OBJDEPS:=$(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(DEPS:%.$(SRCEXT)=%.o))

# Global target
.PHONY: all
all: $(BINDIR)/mulroute

# Main .o dependencies for targets
$(BINDIR)/mulroute: $(BUILDDIR)/main.o

# Global main target rule
$(BINDIR)/mulroute: $(OBJDEPS)
	@mkdir -p $(shell dirname $@)
	$(CXX) $(LDFLAGS) -o $@ $^

# Object files
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(shell dirname $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -MT $@ -c -o $@ $^

# Clean all
.PHONY: clean
clean:
	$(RM) -r $(BUILDDIR) $(BINDIR)

# Automatic dependencies
-include $(patsubst $(SRCDIR),$(BUILDDIR),$(ALLFILES:%.$(SRCEXT)=%.d))
