#include "HT.hpp"
#include <sstream>
#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <cstring>
using namespace std;


class PassMan{
	private:
		struct User
		{
			string username;
			string masterpassword_hash;
			unsigned char encryption_key[crypto_secretbox_KEYBYTES];
			ht_hash_table vault;

			User()=default;
			User(const string& username, const string& masterpassword);
			bool password_verification(const string& password) const;
			static string bytes_to_hex(const unsigned char* bytes, size_t length);
			static vector<unsigned char> hex_to_bytes(const string& hex);
			const unsigned char* get_encryption_key() const { return encryption_key; }
		};

		vector<User> Users;
		int current_user_index=-1;
		string data_file="data.txt";
	public:
		PassMan();
		~PassMan();
		void login(const string& username, const string& password);
		void log_out();
		void add_password(const string& service,const string& username, const string& password);
		void remove(const string& service, const string& username);
		void delete_user(const string& username);
		void register_user(const string& username, const string& masterpassword);
		optional<string> get_password(const string& service, const string& username);
		void list() const;
		void list_users() const;
		const User* get_current_user() const;
		User* get_current_user();  
		bool is_logged_in() const;
		void save_to_file(const string& data_file) const;
		void load_from_file(const string& data_file);
};