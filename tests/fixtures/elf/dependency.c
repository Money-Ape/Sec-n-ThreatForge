#include <stdio.h>

extern int threatforge_test_value(void);

int main(void)
{
    printf(
        "Sec-n-ThreatForge dependency fixture: %d\n",
        threatforge_test_value()
    );

    return 0;
}
