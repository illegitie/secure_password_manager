#include <string>
#include <vector>
#include <optional>
#include <sodium.h>
using namespace std;

class ht_hash_table
{
public:
	//constructors
	explicit ht_hash_table(int init_size=101);
	~ht_hash_table()=default;
	ht_hash_table(const ht_hash_table& ht);
	ht_hash_table(ht_hash_table&& ht) noexcept;

	ht_hash_table& operator=(ht_hash_table&& ht) noexcept;
	ht_hash_table& operator=(const ht_hash_table& ht);
	bool operator==(const ht_hash_table& ht) const;
	bool operator!=(const ht_hash_table& ht) const;

	//methods
	void insert(const string& usrnm, const string& pass, bool not_encrypted=true);
	optional<string> search(const string& usrnm) const;
	void remove(const string& usrnm);
	vector<pair<string, string>> get_all_items() const;
	
	//getters
	int get_size() const;
	int get_count() const;

	//master key methods
	void set_encryption_key(const unsigned char* new_key);
	bool is_initialised() const { return key_initialized;}

private:
	//item struct
	struct ht_item{
		string usrnm;
		string passw;
		enum state
		{
			EMPTY, OCCUPIED, DELETED
		} item_state = EMPTY;

		bool operator==(const ht_item& other) const {
			return usrnm==other.usrnm && passw==other.passw && item_state==other.item_state;
    	}
	} ;
	//table vars
	int size;
	int count;
	std::vector<ht_item> buckets;

	int ht_hash(const string s, const int a, const int num_buckets ) const;
	int get_hash(const string s, const int attempt, const int num_buckets) const;

	void ht_resize(const int base_size);
	void ht_resize_up();
	void ht_resize_down();

	//encryption
	unsigned char encryption_key[crypto_secretbox_KEYBYTES];
	bool key_initialized;

	std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext) const;
};