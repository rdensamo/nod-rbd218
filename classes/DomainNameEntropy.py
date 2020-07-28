import high_entropy_string
from high_entropy_string import PythonStringData
data = PythonStringData(
    string='word',
    node_type='assignment',
    target='myvar',
    patterns_to_ignore=[r'example.com'],
    entropy_patterns_to_discount=[r'/BEGIN.*PUBLIC KEY/']
)
print(data.confidence)
print(data.severity)

# TODO: Some issues with the library zxcvbn they are using
'''
# https://github.com/lyft/high-entropy-string - Not a good library I think
# Documentation: https://pypi.org/project/zxcvbn/
# more documentation https://github.com/dropbox/zxcvbn
# Integer from 0-4 (useful for implementing a strength bar)

  0 # too guessable: risky password. (guesses < 10^3)

  1 # very guessable: protection from throttled online attacks. (guesses < 10^6)

  2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)

  3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)

  4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)

from zxcvbn import zxcvbn

results = zxcvbn('dknasdfksandk').get('score')

print(results)
'''
