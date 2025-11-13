CXX=g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17 -lsodium
INCLUDES = -I/home/kiradplatt/c_p/password-manager/include

#Source files
SRCDIR=/home/kiradplatt/c_p/password-manager/src
SOURCES=$(SRCDIR)/HT.cpp $(SRCDIR)/prime.cpp main.cpp $(SRCDIR)/PassMan.cpp $(SRCDIR)/PassMan_CLI.cpp

TARGET=password_manager

all: $(TARGET) data.txt

$(TARGET) : $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET) 

data.txt:
	touch data.txt


clean:
	rm -f $(TARGET) data.txt

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run

