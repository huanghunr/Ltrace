#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <sys/ptrace.h>

using namespace std;

int antidebug(){
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) 
    {
        puts("Debugger detected."); 
        exit(1);
    }
    return 0;
}

int getmaps(){
    ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        cerr << "can't open /proc/self/maps" << endl;
        return 1;
    }
    string line;
    getline(maps,line);
    maps.close();
    return 0;
}

int main(){
    string s;
    cout << "Input what you want talk to me." << endl;
    cin >> s;
    cout << "I know you say \'" << s << "\'." <<endl;
    getmaps();
    antidebug();

    return 0;
}