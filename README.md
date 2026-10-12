# CYB333-Final-project
Password Strength Analyzer

A dependency-free Python command-line tool that estimates password strength
locally and provides suggestions. It does not save or send the password.

Run it with:

```sh
python3 password_strength.py
```

Type a password at the hidden prompt. You can also pipe one in:

```sh
printf '%s\n' 'your-test-password' | python3 password_strength.py
```

The analyzer assigns a heuristic score from 0 to 100 based on length,
character variety, common passwords, repeated characters, and sequential
patterns. It is an educational estimate, not a guarantee of security.

Run the tests with:

```sh
python3 -m unittest
```
