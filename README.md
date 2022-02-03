# simple-pe-infector
Simple PE Infector

Infecting method:
       find a free space in pe header;
       how it works?
       we find PointerToRawData of .text section because system loader put's her first 
       then we use my simple formulation :
       delta = PointerToRawData - sizeof(code) and scan this space of memmory if it's free infect file and 
       change OEP to delta.
       may be it will be more correct to use 
       delta = PointerToRawData - (sizeof(code) + some more) 

Image presentation:
>       ------------------
>       |  PE HEADER     |
>       |________________|
>       |                |
>       |                |
>       |  OBJECT TABLE  |
>       |________________|                
>       |                |
>       |                |
>       | FREE SPACE     |          
>       | our code       |
>       |________________|
>       |                |
>       |.text section   |
>       | next section   |
>       | next section   |
>       | .............. |
>       |                |
>       ------------------

