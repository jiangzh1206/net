#include <iostream>

class Base
{
	Base(int a)
		: mb(a)
	{
		std::cout << "base: " <<mb << std::endl;
	}
	~Base()
	{
		std::cout << "~base: " << mb << std::endl;
	}

	void pfun()
	{
		std::cout <<"pfun" <<std::endl;
	}

	int mb;

public:
	typedef std::shared_ptr<Base> PTR;

	static PTR Create(int a)
	{
		struct insub : public Base
		{
			insub(int a)
				: Base(a)
			{

			}
			~insub()
			{
				std::cout << "~insub" << std::endl;
			}
		};

		return std::make_shared<insub>(a);
	}

	void pfun1()
	{
		std::cout << "pfun1" << std::endl;
	}
};

//class Sub : public Base
//{
//	Sub(int a)
//		: Base(a)
//	{
//		std::cout <<"sub" << std::endl;
//	}
//};

void func()
{
	//struct insub : public Base
	//{
	//	insub(int a)
	//		: Base(a)
	//	{

	//	}
	//};
}

int main()
{

#if 1
	{
		auto p = Base::Create(10);

		//p->pfun();
		p->pfun1();
	}
#endif // 0


	{
		//auto p = new Base(10);
		//delete p;
		// auto p = std::make_shared<Base>(10);
	}
	
	return 0;
}