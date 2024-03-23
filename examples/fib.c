#include <stdio.h>

int duck(int n)
{

    if (n <= 1)
        return n;
    return duck(n - 1) + duck(n - 2);
}

int main(int argv, char** argc)
{
    int n = 3;
    return duck(n);
}
