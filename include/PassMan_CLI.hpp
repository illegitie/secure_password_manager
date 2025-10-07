#include "PassMan.hpp"


//command line interface
class PassMan_cli{
	private:
		PassMan PM;
		bool running=true;
	public:
		void run();
		void clear_screen() const;
		void process_comand(istringstream& iss);
		void show_help();
};