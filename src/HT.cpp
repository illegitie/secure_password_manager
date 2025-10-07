#include "HT.hpp"
#include "prime.hpp"
#include <cmath>
#include <sodium.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
using namespace std;

ht_hash_table::ht_hash_table(int init_size): size(init_size), count(0), buckets(init_size) {
	if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }
}

ht_hash_table::ht_hash_table(const ht_hash_table& ht) :size(ht.size), count(ht.count), buckets(ht.buckets) {}

ht_hash_table::ht_hash_table(ht_hash_table&& ht) noexcept : size(ht.size), count(ht.count), buckets(move(ht.buckets)){
	ht.size=0;
	ht.count=0;
}

bool ht_hash_table::operator==(const ht_hash_table& ht) const{
	if(count==ht.count && size==ht.size && buckets==ht.buckets) return true;
	return false;
}

bool ht_hash_table::operator!=(const ht_hash_table& ht) const{
	return !(*this==ht);
}

ht_hash_table& ht_hash_table::operator=(const ht_hash_table& ht){
	size=ht.size;
	count=ht.count;
	buckets=ht.buckets;
	return *this;
}

ht_hash_table&  ht_hash_table::operator=(ht_hash_table&& ht) noexcept{
	if(*this!=ht){
		size=ht.size;
		count=ht.count;
		buckets=move(ht.buckets);
		ht.size=0;
		ht.count=0;
	}
	return *this;
}

int ht_hash_table::ht_hash(const string s, const int a, const int num_buckets ) const{
	long hash=0;
	for(char c:s){
		hash=(hash*a+c)%num_buckets;
		if (hash < 0) hash += num_buckets;
	}
	return (int)hash;
}

const int HT_PRIME_1 = next_prime(128);
const int HT_PRIME_2 = next_prime(300);

int ht_hash_table::get_hash(const string s, const int attempt, const int num_buckets)const{
	const int hash_a=ht_hash(s, HT_PRIME_1, num_buckets);
	const int hash_b=ht_hash(s, HT_PRIME_2, num_buckets);
	int index = (hash_a + (attempt * (hash_b + 1))) % num_buckets;
	if (index < 0) index += num_buckets;
	return index;
}

void ht_hash_table::insert(const string& usrnm, const string& pass, bool not_encrypted){
	//add resize later
	string processed_pass=pass;

	if(not_encrypted && key_initialized){
		processed_pass= encrypt(pass);
	}

	const int load=count*100/size;
	if(load>70){
		ht_resize_up();
	}
	int index=get_hash(usrnm, 0, size);
	int i=1;
	while(buckets[index].item_state == ht_item::OCCUPIED){
		if(buckets[index].usrnm==usrnm){
			buckets[index].passw=processed_pass;
			return;
		}
		index=get_hash(usrnm, i, size);
		i++;
	}

	buckets[index]=ht_item{usrnm, processed_pass, ht_item::OCCUPIED};
	count++;
}

optional<string> ht_hash_table::search(const string& usrnm) const{
	int index=get_hash(usrnm,0,size);
	int i=1;
	while( buckets[index].item_state!=ht_item::EMPTY){
		if(buckets[index].item_state==ht_item::OCCUPIED && buckets[index].usrnm==usrnm){
			string passw_decrypted=decrypt(buckets[index].passw);
			return passw_decrypted;
		}
		index=get_hash(usrnm,i,size);
		i++;
	}
	return nullopt;
}

void ht_hash_table::remove(const string& usrnm){
	const int load=count*100/size;
	if(load<10){
		ht_resize_down();
	}

	int index=get_hash(usrnm, 0, size);
	int i=1;
	while(buckets[index].item_state!=ht_item::EMPTY){
		if (buckets[index].item_state==ht_item::OCCUPIED && buckets[index].usrnm==usrnm)
		{
			buckets[index].item_state=ht_item::DELETED;
			count--;
			return;
		}
		index=get_hash(usrnm, i, size);
		i++;
	}
}

int ht_hash_table::get_size() const{
	return size;
}

int ht_hash_table::get_count() const{
	return count;
}


//RESIZING
//load = count of buckets/ total buckets
//up if load>0.7
//down if load<0.1
void ht_hash_table::ht_resize(const int new_size){
	std::vector<ht_item> old_buckets=std::move(buckets); // save old data and clear buckets
	buckets.resize(new_size); //std::vector handles resize
	size=new_size;
	count=0;

	for(auto& item: old_buckets){
		if(item.item_state==ht_item::OCCUPIED){
			int index=get_hash(item.usrnm,0, size);
			int i=1;
			while(buckets[index].item_state==ht_item::OCCUPIED){
				index=get_hash(item.usrnm, i, size);
			}
			buckets[index]=item;
			count++;
		}
	}
}

void ht_hash_table::ht_resize_up(){
	const int new_size=size*2;
	ht_resize(next_prime(new_size));
}

void ht_hash_table::ht_resize_down(){
	const int new_size=size/2;
	ht_resize(next_prime(new_size));
}

//encyption
std::string ht_hash_table::encrypt(const std::string& plaintext){
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof(nonce));

	std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);

	crypto_secretbox_easy(ciphertext.data(), (const unsigned char*)plaintext.data(), plaintext.size(),nonce, encryption_key);

	return std::string((char*)nonce, crypto_secretbox_NONCEBYTES) + std::string((char*)ciphertext.data(), ciphertext.size());
}


std::string ht_hash_table::decrypt(const std::string& ciphertext) const{
	if (ciphertext.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return ""; // Too short to be valid
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, ciphertext.data(), crypto_secretbox_NONCEBYTES);

    std::string encrypted_data = ciphertext.substr(crypto_secretbox_NONCEBYTES);
    std::vector<unsigned char> plaintext(encrypted_data.size() - crypto_secretbox_MACBYTES);

     if (crypto_secretbox_open_easy(plaintext.data(),(const unsigned char*)encrypted_data.data(), encrypted_data.size(),nonce, encryption_key) != 0) {
        return ""; // Decryption failed
    }

    return std::string((char*)plaintext.data(), plaintext.size());
}

void ht_hash_table::set_encryption_key(const unsigned char* new_key){
	//cout << "DEBUG: Setting encryption key, length: " << crypto_secretbox_KEYBYTES << endl;
	memcpy(encryption_key, new_key, crypto_secretbox_KEYBYTES);
	key_initialized=true;
	//cout << "DEBUG: Key set, initialized: " << key_initialized << endl;
}

vector<pair<string, string>> ht_hash_table::get_all_items() const{
	vector<pair<string,string>> items;
	for (const auto& bucket: buckets)
	{
		if(bucket.item_state==ht_item::OCCUPIED){
			items.push_back({bucket.usrnm, bucket.passw});
		}
	}
	return items;
}
