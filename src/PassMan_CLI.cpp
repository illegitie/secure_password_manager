#include "PassMan_CLI.hpp"

void PassMan_cli::clear_screen() const{
	cout<<"\033[2J\033[1;1H";
}



void PassMan_cli::run(){
	cout<<"Password Manager is running --- try 'help' to see commands"<<endl;

	while(running){
		string line;
		if(!getline(cin, line)) break;
		istringstream iss(line);
		process_comand(iss);
	}
}

void PassMan_cli::process_comand(istringstream& iss){
	string command;
	iss>>command;

	//cout << "DEBUG: Command received: '" << command << "'" << endl;

	if(command=="login"){
		clear_screen();
		string username, password;
		if(iss>>username>>password){
			PM.login(username, password);
			return;
		}else{
			cout<<"Usage: login <username> <password>"<<endl;
		}
	}
	else if(command=="register"){
		clear_screen();
		string username, password;
		if(iss>>username>>password){
			PM.register_user(username, password);
			return;
		}else{
			cout<<"Usage : register <username> <password>"<<endl;
		}
	}
	else if(command=="add"){
		clear_screen();
		string service,username, password;
		if(iss>>service>>username>>password){
			PM.add_password(service, username, password);
			return;
		}else{
			cout<<"Usage: add <service> <username> <password>"<<endl;
		}
	}
	else if(command=="get"){
		clear_screen();
		string service, username;
		if(iss>>service>>username){
			optional<string> password=PM.get_password(service, username);
			if(password!=nullopt){
				cout<<"The password is "<<*password<<endl;
			}
			return;
		}else{
			cout<<"Usage: get <service> <username>"<<endl;
		}
	}
	else if(command=="remove"){
		clear_screen();
		string service, username;
		if(iss>>service>>username){
			PM.remove(service,username);
			return;
		}else{
			cout<<"Usage: remove <service> <username>"<<endl;
		}
	}
	else if(command=="delete_user"){
		clear_screen();
		string username;
		if(iss>>username){
			PM.delete_user(username);
			return;
		}else{
			cout<<"Usage: delete_user <username>"<<endl;
		}
	}
	else if(command=="list_users"){
		clear_screen();
		PM.list_users();
		return;
	}
	else if(command=="help"){
		clear_screen();
		show_help();
		return;
	}
	else if(command=="exit"){
		clear_screen();
		running=false;
		return;
	}
	else if(command=="list"){
		clear_screen();
		PM.list();
		return;
	}
	else if(command=="logout"){
		clear_screen();
		PM.log_out();
		return;
	}else if(!command.empty()){
		 cout << "Unknown command: " << command << endl;
	}
}

void PassMan_cli::show_help(){
	cout << "Available commands:\n"
             << "  login <username> <password>\n"
             << "  register <username> <password>\n" 
             << "  add <service> <username> <password>\n"
             << "  get <service> <username>\n"
             << "  remove <service> <username>\n"
             << "  delete_user <username>\n"
             << "  list\n"
             << "  list_users\n"
             << "  logout\n"
             << "  exit\n"
             << "  help" << endl;
    
}