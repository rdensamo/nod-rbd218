'''
CSV2ARFF
Online converter from .csv to WEKA .arff
https://ikuz.eu/csv2arff/
https://github.com/fracpete/python-weka-wrapper3-examples/blob/master/src/wekaexamples/classifiers/classifiers.py
'''
import sys
import os.path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import weka.core.jvm as jvm
from weka.classifiers import Evaluation, Classifier, PredictionOutput, FilteredClassifier, \
    PredictionOutput, Kernel, KernelClassifier
from weka.core.dataset import Instances
from weka.core.classes import Random
import os
import classes.wekahelper as helper
from weka.core.converters import Loader, TextDirectoryLoader

jvm.start(packages=True)


# load ARFF file
helper.print_title("Loading ARFF file Train")
loader = Loader(classname="weka.core.converters.ArffLoader")
print("line 27")
data = loader.load_file(helper.get_data_dir() + os.sep + "train.arff")

# Sets what column is the label attribute
data.class_is_last()


cls = Classifier(classname="weka.classifiers.trees.J48", options=["-C", "0.2"])

evl = Evaluation(data)
print(evl.summary("=== DATA 1 :J48 on anneal (stats) ===", False))

evl.crossvalidate_model(cls, data, 10, Random(1))
print(evl.percent_correct)
print(evl.summary("=== DATA 1 :J48 on anneal (stats) ===", False))
print(evl.class_details())
import weka.plot.classifiers as plcls  # NB: matplotlib is required

plcls.plot_roc(evl, class_index=[0, 1, 2], wait=True)


# load Test ARFF file
helper.print_title("Loading ARFF file Test")
test_data = loader.load_file(helper.get_data_dir() + os.sep + "test.arff")
# Sets what column is the label attribute
test_data.class_is_last()
output = PredictionOutput(classname="weka.classifiers.evaluation.output.prediction.CSV", options=["-distribution"])
cls.build_classifier(data)
evl.test_model(cls, test_data, output)
print(evl.summary())

for index, inst in enumerate(test_data):
    pred = cls.classify_instance(inst)
    dist = cls.distribution_for_instance(inst)
    label = data.class_attribute.value(int(pred))
    print(str(index) + ":", str(dist) + " - " + str(pred) + " - " + label)
    pred = cls.classify_instance(inst)
    dist = cls.distribution_for_instance(inst)

# References :
# Python 3 Weka wrapper API :
# http://fracpete.github.io/python-weka-wrapper3/api.html
# Cooresponding Google Forum :
# https://groups.google.com/g/python-weka-wrapper/c/L8FBbNTaWVw/m/BnmZwKw3BgAJ
# Handling unlabeled data :
# https://groups.google.com/g/python-weka-wrapper/c/gYzG5JZNk10/m/
# Predicting with saved classifier:
# https://groups.google.com/g/python-weka-wrapper/c/cKNK1uHBCYE/m/aDa6uLXGBwAJ


# https://stats.stackexchange.com/questions/109072/10-fold-cross-validation-model-in-weka
# https://fracpete.github.io/python-weka-wrapper/examples.html
# https://github.com/fracpete/python-weka-wrapper3
# https://groups.google.com/g/python-weka-wrapper/c/gYzG5JZNk10/m/
