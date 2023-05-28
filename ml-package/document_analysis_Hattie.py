from cmath import pi
import pickle
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer, porter
import numpy as np
from utils.filter_data import *
import pandas as pd
import re
from nltk.tokenize import sent_tokenize
from utils.csv_output import Classifier_results, CSVOutput
import os
import csv
import requests
from tika import parser
import sys
from datetime import datetime

from deepl_utils import *

techniques_df = pd.read_csv("dataset_new.csv")

def repl(matchobj):
    return ","+ matchobj.group(1) + ","

def remove_empty_lines(text):
	lines = text.split("\n")
	non_empty_lines = [line for line in lines if line.strip() != ""]

	string_without_empty_lines = ""
	for line in non_empty_lines:
		if line != "\n": 
			string_without_empty_lines += line + "\n"

	return string_without_empty_lines 

def combine_text(list_of_text):
    combined_text = ' '.join(list_of_text)
    return combined_text

def lemmatize_set(dataset):
    lemmatizer = WordNetLemmatizer()
    lemmatized_list = []
    for sentence in dataset:
        word_list = word_tokenize(sentence)
        lemma_list = [lemmatizer.lemmatize(w) for w in word_list]
        lemmatized_list.append(' '.join(lemma_list))
    return lemmatized_list

def stemmatize_set(dataset):
    ps = porter.PorterStemmer()
    stemmatize_list = []
    for sentence in dataset:
        word_list = word_tokenize(sentence)
        stemma_list = [ps.stem(w) for w in word_list]
        stemmatize_list.append(' '.join(stemma_list))
    return stemmatize_list

def f_measure(recall, precision):
    if recall != 0 and precision != 0:
        return (2*precision*recall)/(precision+recall)
    else:
        return 0.01

def extract_text(file_path):

    parsed_document = parser.from_file(file_path)
    lines = []
    lines.append(parsed_document['content'])
    # print(lines)
    return lines


ml_model_filenames = ['ml_models/MLP_classifier.sav', 'ml_models/Logreg.sav', 'ml_models/Multinomial_NB.sav', 'ml_models/SVM_Classifier_OVR.sav']
                    #, 'SVM_Classifier_OVO.sav', 'Logreg_normale.sav']

def analyze_all_doc(file_path, model_filenames):

    lines = extract_text(file_path)

    
    ## Apply regex 
    regex_list = load_regex("utils/regex.yml")

    text = combine_text(lines)
    text = re.sub('(%(\w+)%(\/[^\s]+))', repl, text)
    text = apply_regex_to_string(regex_list, text)
    text = re.sub('\(.*?\)', '', text)
    text = remove_empty_lines(text)
    text = text.strip()
    sentences = sent_tokenize(text)

    # print(len(sentences))

    num_sen = len(sentences)

    double_sentences = []

    for i in range(1, len(sentences)):
        new_sen = sentences[i-1] + sentences[i]
        double_sentences.append(new_sen)

    results = []
    
    for model_filename in model_filenames: 
        # load the model from disk
        vectorizer, classifier = pickle.load(open(model_filename, 'rb'))

        stemmatized_set = stemmatize_set(sentences)
        lemmatized_set = lemmatize_set(stemmatized_set)
        x_test_vectors = vectorizer.transform(lemmatized_set)
        predicted = classifier.predict(x_test_vectors)
        #Matrix
        #Vector of vector of probabilities
        predict_proba_scores = classifier.predict_proba(x_test_vectors)
        #Identify the indexes of the top predictions (increasing order so let's take the last 2, highest proba)
        top_k_predictions = np.argsort(predict_proba_scores, axis = 1)[:,-2:]
        #Get classes related to previous indexes
        top_class_v = classifier.classes_[top_k_predictions]

        results = {'ID': [], 'Name': [], 'Sentence': [],}
        df = pd.DataFrame(results)

        thresholds = [0.10, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        for threshold in thresholds: 
            # accepted = []

            for i in range(0,len(predict_proba_scores)):
                sorted_indexes = top_k_predictions[i]
                top_classes = top_class_v[i]
                proba_vector = predict_proba_scores[i]
                predicted_labels = []
                label_name = []
                used_sentences = []
                if proba_vector[sorted_indexes[1]] > threshold:
                    # accepted.append(top_classes[1])
                    predicted_label = top_classes[1]
                    label_name = " ".join(re.findall("[a-zA-Z]+", techniques_df[techniques_df["label_subtec"] == predicted_label]["tec_name"].head(1).to_string()))
                    predicted_labels.append(predicted_label)
                    used_sentences.append(sentences[i])
                    result = {"ID": predicted_label, "Name": label_name, "Sentence": sentences[i],}
                    
                    df.loc[len(df)] = result
    df.drop_duplicates(inplace=True)
    return df

# total arguments
n = len(sys.argv)
print("Start analysing", n-1, "documents...")

for i in range(1, n):
    file_path = sys.argv[i]
    results = analyze_all_doc(file_path, ml_model_filenames)

    index = 0
    for char in file_path:
        if char == '.':
            break
        index+=1

    new_file_path = file_path[:index] + '_result.xlsx'
    # print(new_file_path)
    results.to_excel(new_file_path, index=False)
    print("Analysis progress: ", i, "/", n-1, sep="")

    # convert results xlsx to csv 
    technique_list = pd.read_excel(new_file_path, 'Sheet1')
    csv_file_path = file_path[:index] + '_result.csv'
    technique_list.to_csv(csv_file_path)
    print("Technique list result is successfully converted to csv file.")

    # filter csv to extract technique IDs only
    filtered_csv = pd.read_csv(csv_file_path, usecols=['ID'])
    txt_file_path = file_path[:index] + '_result.txt'
    filtered_csv.to_csv(txt_file_path, header=False, index=False)
    print("List of Technique ID is successfully extracted to txt file.")