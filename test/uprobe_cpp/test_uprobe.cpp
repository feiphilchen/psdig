#include <iostream>
using namespace std;

typedef enum my_enum_e {
  EN_0=0,
  EN_1
} my_enum_t ;


class MyClass {         // The class
  public:               // Access specifier
    void myMethod(int);    // Method/function declaration
};

class MyClass2 {         // The class
  public:               // Access specifier
    void myMethod(string);    // Method/function declaration
    my_enum_t myMethod2(my_enum_t);    // Method/function declaration
};

// Method/function definition outside the class
void MyClass::myMethod(int a1) {
  printf("MyClass::myMethod(this=%p, a1=%d) => void\n", this, a1);
}

// Method/function definition outside the class
void MyClass2::myMethod(string a1) {
      printf("MyClass2::myMethod(a1=%p) => void\n", &a1);
}

// Method/function definition outside the class
my_enum_t MyClass2::myMethod2(my_enum_t x) {
     printf("MyClass2::myMethod2(this=%p, x=%u) => %u\n", this,x, x);
     return x;
}

namespace MyNamespace2
{
class MyClass {         // The class
  public:               // Access specifier
    void myMethod1(int);    // Method/function declaration
};

class MyClass2 {         // The class
  public:               // Access specifier
    MyClass2(long long xxxx) {
        printf("MyNamespace2::MyClass::MyClass2(xx=%lld)\n", xxxx);
    }
    ~MyClass2() {
         printf("~MyNamespace2::MyClass::MyClass2()\n");
    }
    int myMethod(string);    // Method/function declaration
    int myMethod(unsigned int, char);    // Method/function declaration
};

// Method/function definition outside the class
void MyClass::myMethod1(int a1) {
    printf("MyNamespace2::MyClass::myMethod1(a1=%d) => void\n", a1);
}

// Method/function definition outside the class
int MyClass2::myMethod(string a1) {
    printf("MyNamespace2::MyClass2::myMethod(a1=%p) => -1\n", &a1); 
    return -1;
}

// Method/function definition outside the class
int MyClass2::myMethod(unsigned int x, char ch) {
    printf("MyNamespace2::MyClass2::myMethod(x=%u, ch=%u) => 0\n", x, ch);
  return 0;
}

}

int main() {
  //MyClass myObj;     // Create an object of MyClass
  MyNamespace2::MyClass myObj1;     // Create an object of MyClass
  MyNamespace2::MyClass2 myObj2(10);     // Create an object of MyClass
  MyClass               myObj3;
  MyClass2              myObj4;
  string s = "foo";
  my_enum_t y = EN_1;
  printf("%p\n", &y);
  myObj1.myMethod1(1);
  myObj2.myMethod(s);
  myObj2.myMethod(10, 'i');
  myObj3.myMethod(10);
  myObj4.myMethod2(y);
  return 0;
}

