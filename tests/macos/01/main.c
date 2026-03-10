extern int test();
extern int printf(const char *, ...);
int another = 3;

int main() {
    printf("test() returned %d\n", test());
    return test() - 20;
}