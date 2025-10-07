CXX=g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17 -lsodium
INCLUDES = -I/home/kiradplatt/c_p/password-manager/include

#Source files
SRCDIR=/home/kiradplatt/c_p/password-manager/src
SOURCES=$(SRCDIR)/HT.cpp $(SRCDIR)/prime.cpp main.cpp $(SRCDIR)/PassMan.cpp $(SRCDIR)/PassMan_CLI.cpp

TARGET=password_manager

all: $(TARGET)

$(TARGET) : $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run

