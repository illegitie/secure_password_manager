#include "PassMan.hpp"
using namespace std;


PassMan::User::User(const string& username, const string& masterpassword): username(username){
	//hash master password
	//cout << "DEBUG: Creating user " << username << "with password "<<masterpassword<<endl;;
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash(hash, sizeof hash,
                      (const unsigned char*)masterpassword.c_str(), 
                      masterpassword.length(), NULL, 0);
	masterpassword_hash = bytes_to_hex(hash, sizeof(hash));

	//derive key from masterpassword_hash
	unsigned char salt[crypto_pwhash_SALTBYTES];
	crypto_generichash(salt, sizeof salt,
                      (const unsigned char*)username.c_str(), 
                      username.length(), NULL, 0);

	if (crypto_pwhash(encryption_key, sizeof encryption_key,  
                     masterpassword.c_str(), masterpassword.length(),
                     salt,
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE, 
                     crypto_pwhash_ALG_DEFAULT) != 0){
        throw runtime_error("Key derivation failed - out of memory");
    }
	//cout << "DEBUG: Derived key, setting vault key..." << endl;
	vault.set_encryption_key(encryption_key);
	//cout << "DEBUG: Vault initialized: " << vault.is_initialised() << endl;
}

string PassMan::User::bytes_to_hex(const unsigned char* bytes, size_t length){
	string hex;
    for (size_t i = 0; i < length; i++) {
        char buf[3];
        sprintf(buf, "%02x", bytes[i]);
        hex += buf;
    }
    return hex;
}
vector<unsigned char> PassMan::User::hex_to_bytes(const string& hex){
	vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}



bool PassMan::User::password_verification(const string& password) const{
	//cout << "DEBUG Verify: Checking password '" << password << "' for user '" << username << "'" << endl;
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash(hash, sizeof hash,
                      (const unsigned char*)password.c_str(), 
                      password.length(), NULL, 0);
	string password_hash = bytes_to_hex(hash, sizeof(hash));
	//cout << "DEBUG Verify: Input hash: " << password_hash << endl;
    //cout << "DEBUG Verify: Match: " << (masterpassword_hash == password_hash ? "YES" : "NO") << endl;
	return masterpassword_hash==password_hash;
}

void PassMan::register_user(const string& username, const string& masterpassword){
	for(const auto& user: Users){
		if(username==user.username){
			cout<<"User is already registered"<<endl;
			return;
		}
	}

	User new_user(username, masterpassword);
	Users.push_back(new_user);
	cout<<"User "<<username<<" is registered"<<endl;
}

void PassMan::add_password(const string& service,const string& username, const string& password){
	if (!is_logged_in())
	{
		cout<<"Not logged in!"<<endl;
		return;
	}
	User* current_user=get_current_user();
	//cout << "DEBUG: vault initialized: " << current_user->vault.is_initialised() << endl;
	if(!current_user->vault.is_initialised()){
		cout<<"Vault is not initialised!"<<endl;
		return;
	}

	string service_username= service + ":" + username;
	cout<<"Password is added!"<<endl;
	current_user->vault.insert(service_username, password);
}
void PassMan::remove(const string& service, const string& username){
	if(!is_logged_in()){
		cout<<"Not logged in"<<endl;
		return;
	}	
	User* current_user=get_current_user();
	if(!current_user->vault.is_initialised()){
		cout<<"Vault is not initialised!"<<endl;
		return;
	}

	string service_username=service+":"+username;
	current_user->vault.remove(service_username);
	cout<<"Password removed successfuly"<<endl;
}

void PassMan::delete_user(const string& username){
	for(auto it=Users.begin(); it!=Users.end(); it++){
		if(it->username==username){
			if(current_user_index!=-1 && &Users[current_user_index]==&*it){
				log_out();
			}
			Users.erase(it);
			cout<<"User "<<username<<" is deleted"<<endl;
			return;
		}
	}
	cout<<"User "<<username<<" is not found"<<endl;
	return;
}

void PassMan::list_users() const{
	for (const auto& user: Users)
	{
		cout<<user.username<<endl;
	}
}


optional<string> PassMan::get_password(const string& service, const string& username){ 
	if(!is_logged_in()) {
		cout<<"Not logged in!"<<endl; 
		return nullopt;
	}
	User* current_user=get_current_user();
	string service_username= service + ":" + username;
	auto result=current_user->vault.search(service_username);
	
	if(!result){
		cout<<"Password not found"<<endl;
		return nullopt;
	}
	
	return result;
}

void PassMan::list() const{
	if(!is_logged_in()){
		cout<<"Cannot list: user is not logged"<<endl;
		return;
	}
	const User* current_user=get_current_user();
	vector<pair<string,string>> all_passwords=current_user->vault.get_all_items();
	if(all_passwords.empty()){
		cout<<"No passwords stored!"<<endl;
		return;
	}
	for(const auto& item: all_passwords){
		size_t pos= item.first.find(":");
		string service=item.first.substr(0,pos);
		string username=item.first.substr(pos+1);

		auto password =current_user->vault.search(item.first);
		if (password)
		{
			cout<<"Service: "<<service<<" | Username: "<<username<<" | Password: "<<*password<<endl;
		}
	}
}

void PassMan::log_out(){
	current_user_index=-1;
	cout<<"Logged out"<<endl;
}

const PassMan::User* PassMan::get_current_user() const{
	if(is_logged_in()){
		return &Users[current_user_index];
	}
	return nullptr;
}

PassMan::User* PassMan::get_current_user(){
	if(is_logged_in()){
		return &Users[current_user_index];
	}
	return nullptr;
}  

bool PassMan::is_logged_in() const{
	return current_user_index!=-1;
}

void PassMan::login(const string& username, const string& password){
	for(size_t i=0; i<Users.size(); i++){
		if(Users[i].username==username){
			if(Users[i].password_verification(password)){
				
				current_user_index=int(i);
				Users[i].vault.set_encryption_key(Users[i].get_encryption_key());
				
				cout << "Login successful! Welcome " << username << endl;
				return;
			}else{
			cout<<"Wrong password!"<<endl;
			return;
			}
		}
	}
	cout<<"Username is not found!"<<endl;
}

void PassMan::save_to_file(const string& data_file) const{
	ofstream file(data_file);
	if (!file){
		cerr<<"Error: Cannot save to "<<data_file<<endl;
		return;
	}

	for(const auto& user: Users){
		file<<"[USER]\n";
		file<<user.username<<" "<<user.masterpassword_hash<<" "<<User::bytes_to_hex(user.encryption_key,crypto_secretbox_KEYBYTES)<<"\n";

		file<<"[PASSWORDS]\n";
		auto items=user.vault.get_all_items(); // vector<pair<string,string>>
		for(const auto& item: items){
			size_t pos=item.first.find(":");
			string service=item.first.substr(0, pos);
			string username=item.first.substr(pos+1);
			string encrypted_password=item.second;

			file<<service<<" "<<username<<" "<<User::bytes_to_hex((unsigned char*)encrypted_password.data(), encrypted_password.length())<<"\n";
		}
		file<<"[END_USER]\n\n";
	}
	cout<<"Saved"<<Users.size()<<"users to "<<data_file<<endl;

}

void PassMan::load_from_file(const string& data_file){
	ifstream file(data_file);
	if(!file){
		cerr<<"Nothing to load from "<<data_file<<endl;
		return;
	}

	string line;
	User* current_user=nullptr;

	while(getline(file,line)){
		//cout << "DEBUG: Read line: '" << line << "'" << endl;
		if(line=="[USER]"){
			if(getline(file,line)){
				//cout << "DEBUG: User data: '" << line << "'" << endl;
				istringstream iss(line);
				string username, password_hash, hex_key;
				if(iss>>username>>password_hash>>hex_key){
					Users.emplace_back();
					current_user=&Users.back();
					current_user->username=username;
					current_user->masterpassword_hash=password_hash;
					//cout << "DEBUG: Created user: " << username << endl;
					auto key_bytes=User::hex_to_bytes(hex_key);
					memcpy(current_user->encryption_key, key_bytes.data(), crypto_secretbox_KEYBYTES);
					current_user->vault.set_encryption_key(current_user->encryption_key);
				}
			}
		}
		else if(line=="[PASSWORDS]" && current_user){
			//cout << "DEBUG: Reading passwords for " << current_user->username << endl;
			while(getline(file,line) && line!="[END_USER]"){
				//cout << "DEBUG: Password line: '" << line << "'" << endl;
				istringstream iss(line);
				string service,username,hex_password;
				if(iss>>service>>username>>hex_password){
					//cout << "DEBUG: Parsed - service:" << service << " username:" << username << " encoded:" << hex_password << endl;
					auto encrypted_bytes=User::hex_to_bytes(hex_password);
					string encrypted_password(encrypted_bytes.begin(),encrypted_bytes.end());
					//cout << "DEBUG: Decoded length: " << encrypted_password.length() << endl;
					string usrnm=service+":"+username;
					current_user->vault.insert(usrnm, encrypted_password, false);
					//cout << "DEBUG: Inserted into vault" << endl;
				}
			}
		}
	}
}

PassMan::PassMan(){
	load_from_file(data_file);
}

PassMan::~PassMan(){
	save_to_file(data_file);
}
