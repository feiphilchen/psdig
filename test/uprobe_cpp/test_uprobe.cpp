#include <iostream>
using namespace std;
class MyClass {         // The class
  public:               // Access specifier
    void myMethod1(int);    // Method/function declaration
};

class MyClass2 {         // The class
  public:               // Access specifier
    void myMethod(string);    // Method/function declaration
    void myMethod2(unsigned int, char);    // Method/function declaration
};

// Method/function definition outside the class
void MyClass::myMethod1(int a1) {
  printf("Hello World! a1=%d\n", a1);
}

// Method/function definition outside the class
void MyClass2::myMethod(string a1) {
  printf("a1 size:%lu\n" , sizeof(a1));
  printf("Hello World! a1=%s %p\n", a1.c_str(), &a1);
}

// Method/function definition outside the class
void MyClass2::myMethod2(unsigned int x, char ch) {
  printf("Hello World! x=%u %u\n", x, ch);
}

namespace MyNamespace
{
class MyClass {         // The class
  public:               // Access specifier
    void myMethod1(int);    // Method/function declaration
};

class MyClass2 {         // The class
  public:               // Access specifier
    void myMethod(string);    // Method/function declaration
    void myMethod2(unsigned int, char);    // Method/function declaration
};

// Method/function definition outside the class
void MyClass::myMethod1(int a1) {
  printf("Hello World! a1=%d\n", a1);
}

// Method/function definition outside the class
void MyClass2::myMethod(string a1) {
  printf("a1 size:%lu\n" , sizeof(a1)); 
  printf("Hello World! a1=%s %p\n", a1.c_str(), &a1);
}

// Method/function definition outside the class
void MyClass2::myMethod2(unsigned int x, char ch) {
  printf("Hello World! x=%u %u\n", x, ch);
}

}

namespace MyNamespace2
{
class MyClass {         // The class
  public:               // Access specifier
    void myMethod1(int);    // Method/function declaration
};

class MyClass2 {         // The class
  public:               // Access specifier
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
  MyNamespace2::MyClass2 myObj2;     // Create an object of MyClass
  string s = "foo";

  myObj1.myMethod1(1);
  myObj2.myMethod(s);
  myObj2.myMethod(10, 'i');
  //myObj2.myMethod2(3, 'i');
  return 0;
}

