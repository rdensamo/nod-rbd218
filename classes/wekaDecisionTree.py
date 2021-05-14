'''
CSV2ARFF
Online converter from .csv to WEKA .arff
https://ikuz.eu/csv2arff/
https://github.com/fracpete/python-weka-wrapper3-examples/blob/master/src/wekaexamples/classifiers/classifiers.py
'''

import traceback
import weka.core.jvm as jvm
import weka.core.converters as conv
from weka.classifiers import Evaluation, Classifier, PredictionOutput, FilteredClassifier, \
    PredictionOutput, Kernel, KernelClassifier
from weka.filters import Filter
from weka.core.classes import Random
import os
# import wekaexamples.helper as helper
import classes.wekahelper as helper
from weka.core.converters import Loader, TextDirectoryLoader

jvm.start(packages=True)

# data = conv.load_any_file(helper.get_data_dir() + os.sep + "iris.csv")

# load CSV file
helper.print_title("Loading ARFF file Train")
# loader = Loader(classname="weka.core.converters.CSVLoader")
loader = Loader(classname="weka.core.converters.ArffLoader")
# data = loader.load_file(helper.get_data_dir() + os.sep + "glass_training set.arff")
# domain_scoring_LABEL_removedElk_4_22_train.csv
# data = loader.load_file(helper.get_data_dir() + os.sep + "domain_scoring_LABEL_removedElk_4_22_train.arff")
# combined_datasets_513_removed_domains_v1.arff
data = loader.load_file(helper.get_data_dir() + os.sep + "combined_datasets_513_removed_domains_v1.arff")
# data = loader.load_file(helper.get_data_dir() + os.sep + "sample_train.arff")
data.class_is_last()  # Sets what column is the label attribute
# print("data 1 ", data)

cls = Classifier(classname="weka.classifiers.trees.J48", options=["-C", "0.2"])

evl = Evaluation(data)
evl.crossvalidate_model(cls, data, 10, Random(1))
print(evl.summary("=== DATA 1 :J48 on anneal (stats) ===", False))
#
# References : https://github.com/fracpete/python-weka-wrapper-examples/blob/master/src/wekaexamples/core/converters.py

from weka.filters import Filter
# TODO: still need to figure out how to remove bad attributes to improve accuracy
# TODO: may want to use RandomForest instead for better accuracy but more
# TODO: complex model but also less prone to overfitting
from weka.experiments import SimpleCrossValidationExperiment, SimpleRandomSplitExperiment, Tester, ResultMatrix
import weka.core.converters as converters

# Trying to run it on unlabeled data for prediction ** most important test **
# TODO : next I want to get confidence scores ? Then we can use those as risk scores ?
# https://github.com/fracpete/python-weka-wrapper3-examples/blob/master/src/wekaexamples/classifiers/train_test_split.py
# load CSV file
helper.print_title("Loading ARFF file Test")
# loader = Loader(classname="weka.core.converters.CSVLoader")
# data2 = loader.load_file(helper.get_data_dir() + os.sep + "domain_scoring_LABEL_onlyELK.csv")
# data2 = loader.load_file(helper.get_data_dir() + os.sep + "domain_scoring_LABEL_removedElk.csv")
data2 = loader.load_file(helper.get_data_dir() + os.sep + "2_domain_scoring_LABEL_onlyELK_MODIFIED_4_22_2021_test.arff")
# 2_domain_scoring_LABEL_onlyELK_MODIFIED_4_22_2021_test.arff
# data2 = loader.load_file(helper.get_data_dir() + os.sep + "glass_test set.arff")
# data2 = loader.load_file(helper.get_data_dir() + os.sep + "sample_test.arff")
data2.class_is_last()  # Sets what column is the label attribute
output = PredictionOutput(classname="weka.classifiers.evaluation.output.prediction.CSV", options=["-distribution"])
cls.build_classifier(data)
evl.test_model(cls, data2, output)
print(evl.summary())
# helper.print_info("Predictions:")
# print(output.buffer_content())

for index, inst in enumerate(data2):  # new data
    pred = cls.classify_instance(inst)
    dist = cls.distribution_for_instance(inst)
    label = data.class_attribute.value(int(pred))
    print("line 68: ", str(dist) + " - " + str(pred) + " - " + label)
    pred = cls.classify_instance(inst)
    # print("pred", pred)
    dist = cls.distribution_for_instance(inst)
    # print(str(index + 1) + ": predicted label index=" + str(pred) + ", class distribution=" + str(dist))
# May not be able to use this ??
'''
cls.build_classifier(data)  # use original data
# print("data 2 point ", data2)
for index, inst in enumerate(data2):  # new data
    pred = cls.classify_instance(inst)
    dist = cls.distribution_for_instance(inst)
    label = data.class_attribute.value(int(pred))
    # print(str(dist) + " - " + str(pred) + " - " + label)
    pred = cls.classify_instance(inst)
    # print("pred", pred)
    dist = cls.distribution_for_instance(inst)
    print(str(index+1) + ": predicted label index=" + str(pred) + ", class distribution=" + str(dist))
evl = Evaluation(data2)
evl.crossvalidate_model(cls, data2, 10, Random(1))
#print(evl.summary("=== DATA 2 : J48 on anneal (stats) ===", False))
# Python 3 Weka wrapper API :
# http://fracpete.github.io/python-weka-wrapper3/api.html
# Cooresponding Google Forum :
# https://groups.google.com/g/python-weka-wrapper/c/L8FBbNTaWVw/m/BnmZwKw3BgAJ
'''

# unlabeled data :
# https://groups.google.com/g/python-weka-wrapper/c/gYzG5JZNk10/m/

# TODO : predicting with saved classifier
# https://groups.google.com/g/python-weka-wrapper/c/cKNK1uHBCYE/m/aDa6uLXGBwAJ


# TODO:
# 1) Try to feed datum from command line to weka
# 2) Get decision tree
