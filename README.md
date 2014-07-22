kpabe
=====

kpabe toolkit in Java

This software is a Java realization for "key-policy attribute based
encryption" (KP-ABE).

To use this software, you will need to have the Java Pairing Based Cryptography
Library(jPBC) library installed. You can get it from the following page:

   http://gas.dia.unisa.it/projects/jpbc/

Your mush be responsible for the problem caused by using the code.

Note: The original KP-ABE scheme proposed by Goyal-Pandey-Sahai-Waters works fine. 
There is some problem with SerializationUtils that convert files to byte[] and then to PBC element.
I am also working on parsing policy to make it more user-friendly.

Welcome to my REU site for more information on the project.

  https://sites.google.com/a/ualr.edu/reu-project-by-liang-zhang/
  
In addition, some of my code is adapted from junwei-wang's Java realization for
"ciphertext-policy attribute-based encryption" (CP-ABE). You can go to his website for
more information on CP-ABE.

http://junwei-wang.github.io/cpabe/

Thanks!
