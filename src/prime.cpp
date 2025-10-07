#include <cmath>
#include "prime.hpp"

bool is_prime(const int x){
	if(x<2) return false;
	if(x<4) return true;
	if((x%2)==0) return false;
	for (int i=3; i*i<x; i+=2){
		if((x%i)==0) return false;
	}
	return true;
}

int next_prime(int x){
	while(!is_prime(x)){
		x++;
	}
	return x;
}