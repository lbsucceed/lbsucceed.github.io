
+++
title = "Decorator learning Python"
date = 2024-01-24
updated = 2024-01-24
[taxonomies]
categories = ["Python Tips"]
tags = ["python","Tips"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++

## 装饰器初步

所谓装饰器，decorators，就是修改其他函数的功能的函数。他们有助于让我们的代码更简短，也更Pythonic。

先让我们了解一下普通的函数。

**位置传参和可变长度搭配传参**

```python
def foo5(value, *args):
	print(value, args)

foo5(1, 2, 3, 4, 5)  # 第一个参数按照位置传参，剩余的被 *args 收集
```

**接收任意长度的key=value形式的参数，并收集到一个字典内，一般在所有的参数的后面**

```python
def foo7(**kwargs):
	print(kwargs)  # {'a': 1, 'b': 2, 'c': 3}

foo7(a=1, b=2, c=3)
```

**函数可以被引用** 因为都是对象`

```python
def foo():  
    return 'ok'  
f1 = foo()  
print('f1: ',f1)        		# f1:  ok  
f2 = foo  
print('f2: ',f2)        		# f2:  <function foo at 0x00373A98>  
print('f2(): ',f2())    		# f2():  ok  
```

而在第5行将`foo`函数被变量`f2`引用后，此时打印的（第6行）为`foo`的内存地址，而`f2`加括号（第7行）触发了`foo`函数的执行。返回"ok"。

**函数可以当做函数的参数**

```python
def bar():  
    a = 1  
    print('a =',a)  
def foo(b):  
    pass  
foo(bar)            
```

上例中，`bar`函数被当作`foo`函数的实参传递给形参`b`。

**函数可以当做函数的返回值**

```python
def bar():  
    print('bar function')  
def foo():  
    return bar  
f = foo()  
print(f)  					# <function bar at 0x00FA3A98>  
f()  						# bar function  
```

上例中，`foo`函数返回的是`bar`函数，`foo`函数将结果赋值给`f`。在第6行打印的时候可以看到打印的`bar`函数的内存地址，那么变量f加括号相当于`bar`函数加括号，执行`bar`函数的`print`。

**函数可以当做容器类型的元素**

通过与用户交互，模拟文件的增删改查操作，每个函数对应不同的操作，暂时用打印来代替具体的操作。通过这个练习来理解为什么说函数可以当做容器类型的元素。

```python
def add():  
    print('add function')  
def update():  
    print('update function')  
def select():  
    print('select function')  
def delete():  
    print('delete function')  
dict = {'add': add, 'update': update, 'select': select, 'delete': delete} 
while 1:  
    cmd = input('Enter command: ').strip()  
    if cmd in dict:  
        dict[cmd]()  
    elif cmd == 'q':  
        print('goodbye')  
        break  
    else:  
        print('Error command')  
        continue  
```

代码第`1~7`行，定义增删改查四个函数，`print`就算代替具体的操作了。第9行定义一个字典。第10行开始，写了一个循环用来与用户进行交互。第11行获取用户输入的内容，第12行开始判断，用户输入的`cmd`是否在`dict`内，如果在说明`cmd`是`dict`的`key`，那么`dict[cmd]`取出对应的`value`，而`value`是对应的增删改查的函数，找到函数加括号（第13行）就能执行这个函数。完成增删改查的操作（执行print）。而第14行当用户输入"q"的时候，退出程序。第17行是当用户输入无效的命令的时候，提示并从新循环等待输入。运行结果如下例所示：

```shell
Enter command: asss     # 输入错误命令，会提示命令无效，并等待用户重新输入
Error command           
Enter command: add      # 输入正确的命令，执行对应的函数，并等待用户重新输入  
add function      
Enter command: q        # 用户输入"q"，则退出程序  
goodbye  
  
Process finished with exit code 0  
```

### 闭包函数

嵌套函数还有一种特殊的表现形式——闭合(closure)，我们称这种特殊的嵌套函数为闭包函数。

```python
def foo():  
    x = 1  
    y = 2  
    def bar():  
        print(x, y)  
    return bar  
f = foo()  					# 变量f就是bar函数，加括号就能执行
print(f)    					# <function foo.<locals>.bar at 0x01136738>  
print(f.__closure__)            # (<cell at 0x011BD070: int object at 0x604999C0>, <cell at 0x011BDED0: int object at 0x604999D0>)  
print(f.__closure__[0].cell_contents)   		# 1  
print(f.__closure__[1].cell_contents)   		# 2  
```

参考上例来讨论一下闭包函数的特点。

闭包函数是指在函数（foo函数）内部定义的函数（bar函数），称为内部函数，该内部函数包含对嵌套作用域的引用，而不是全局作用域的引用。那么，该内部函数称为闭包函数。

闭包函数包含对嵌套作用域的引用，而不是全局作用域的引用。这句话通过第8行的打印，我们分析，虽然打印的结果只是bar函数的内存地址，但是其不仅仅是明面上的内存地址那么简单，这个bar函数还自带其外部的嵌套作用域。闭包函数相关的`__closure__`属性，`__closure__`属性定义的是一个包含 cell 对象的元组，其中元组中的每一个 cell 对象用来保存局部作用域中引用了哪些嵌套作用域变量。第9行打印的结果印证了这一点。我们在嵌套作用域内定义了2个变量x、y。而第9行的打印结果为一个元组，其内存在两个元素地址。我们通过第10~11行的打印取元组的第1个、第2个元素进一步验证，我们顺利的拿到了存在与嵌套函数x、y的变量值。

```python
x = 1  
def foo():  
    def bar():  
        print(x)  
    return bar  
f = foo()  
print(f.__closure__)    # None  
```

上例也证明内部函数bar只包含对嵌套作用域的引用，而不是全局作用域的引用，因为第4行引用的变量是全局的变量x。而通过第7行打印也证明这一点，bar函数的`__closure__`属性返回为None，也就是空值。如果嵌套作用域内有变量x，那么`__closure__`属性内就会存在嵌套作用域的变量地址。

```python
def f1():  
    x = 1  
    y = 2  
    def b1():  
        print(x)  
    return b1  
f = f1()  
print(f.__closure__)  # (<cell at 0x00B6D070: int object at 0x604999C0>,)  
def f2():  
    x = 1  
    y = 2  
    def b2():  
        print(x, y)  
    return b2  
f = f2()  
print(f.__closure__)  # (<cell at 0x0123DED0: int object at 0x604999C0>, <cell at 0x01248430: int object at 0x604999D0>)  
```

但有一点需要说明的是，不管嵌套作用域内定义了多少变量。而内部函数包含对嵌套作用域的引用这句话。指的是内部函数的`__closure__`属性内的元组内元素个数，取决于在局部作用域中对嵌套作用域中哪些变量的引用。如上例，在f1函数内定义了两个变量，但在b1函数只引用了x这一个变量。所以b1函数的`__closure__`属性内只存在一个嵌套作用域的变量地址。而第13行在局部作用域引用了两个嵌套作用域的变量。故b2的`__closure__`内就有两个值。

上面的例子都为闭包函数的一层嵌套形式，下面的例子为闭包函数的两层嵌套形式。跟一层闭包函数一样，最内层的函数，包含对嵌套作用域的引用。

```python
def foo():  
    name = 'oldboy'  
    def bar():  
        money = 1000  
        def oldboy_info():  
            print('%s have money: %s' % (name, money))  
        return oldboy_info  
    return bar  
bar = foo()  
oldboy_info = bar()  
oldboy_info()  					 # oldboy have money: 1000  
print(oldboy_info.__closure__)      # (<cell at 0x0090D050: int object at 0x009B9570>, <cell at 0x00900FF0: str object at 0x0090D060>)  
print(oldboy_info.__closure__[0].cell_contents)  		# 1000  
print(oldboy_info.__closure__[1].cell_contents)  		# oldboy  
```

上例中，第6行的打印的name和money变量，是对上级作用域（bar函数）和顶级嵌套作用域（foo函数）的引用。通过第13~14行的打印可以看出，oldboy_info函数的`__closure__`内包含了2个变量。

### Understanding Decorators in Python

为了锻炼英语，这里使用英文。

A decorator in Python is a powerful feature that allows us to modify or extend the behavior of functions. It can be thought of as a more advanced form of closure. Here, I'll explain this concept through examples.

To measure the time taken by a function, you might first try something like this:

```python
import time
def func():
    start = time.time()
    print('function is running..')
    time.sleep(1)
    print('function run time ', time.time() - start)
func()
# output:
#function is running..
# function run time  3.0023677349090576
```

However, if we want to measure the time of **1 million** function calls, this approach becomes inefficient. Instead, we can create another function to measure the execution time of other functions.

We can define a `timer` function to measure the execution time of another function:

```python
import time  
def timer(func):  
    ''' prints function time '''  
    start = time.time()  
    func()                  	# 调用函数的执行  
    print('function %s run time %s' % (func.__name__, time.time() - start)) # 打印函数执行的时间  
def f1():  
    time.sleep(1)   			# 通过睡眠，模拟函数执行的时间  
def f2():  
    time.sleep(2)  
timer(f1)  					# function f1 run time 1.0005981922149658  
timer(f2)  					# function f2 run time 2.00011944770813  
```



While this approach works, it can be optimized for efficiency. Instead of calling the `timer` function directly each time, we can use **closures** to improve it.

```python
import time

def timer(func):
    ''' Prints function execution time '''
    def wrapper():
        start = time.time()
        func()  # Execute the original function
        print('Function %s run time: %s' % (func.__name__, time.time() - start))
    return wrapper

def f1():
    time.sleep(1)  # Simulate function execution time

def f2():
    time.sleep(2)

print('Before assigning f1:', f1)  # <function f1 at 0x005D6738>
f1 = timer(f1)  # f1 is now wrapped with the timer decorator
print('After assigning f1:', f1)  # <function timer.<locals>.wrapper at 0x00E43270>

f2 = timer(f2)  # f2 is also wrapped with the timer decorator
f1()  # Function f1 run time: 1.0000762939453125
f2()  # Function f2 run time: 2.000044345855713

```

For the example above, 	we can try to use the assignment to simplify the operation.

But we can also use the decorator to get rid of it,then use the decorator:

```python
import time  
def timer(func):  
    ''' prints function time '''  
    def wrapper():  
        start = time.time()  
        func()  
        print('function %s run time %s' % (func.__name__, time.time() - start))  
    return wrapper  
@timer  
def f1():  
    time.sleep(1)  
@timer  
def f2():  
    time.sleep(2)  
f1()  # function f1 run time 1.0000762939453125  
f2()  # function f2 run time 2.000044345855713  
```

In this version, we use the `@timer` syntax to apply the decorator directly to the functions `f1` and `f2`. This is the power of decorators — it simplifies the process, making your code cleaner and more readable. This is what the virtue of the decorator.

### Conclusion

As demonstrated, decorators offer a clean and efficient way to modify or extend the behavior of functions. By using decorators, you can easily add common functionality, like timing, logging, or validation, to multiple functions without repeating code. This makes your code more modular and maintainable.