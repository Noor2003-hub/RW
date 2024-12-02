from transformers import pipeline
import numpy as np
from numpy.linalg import norm

# Load pre-trained transformer model for feature extraction
model = pipeline('feature-extraction', model='bert-base-multilingual-cased')

# Dataset of sentences
sentences = [
    "يكتب الطالب الدرس",
    "كتابة المقال كانت جيدة",
    "هو يحب الكتابة كل يوم",
    "الطفل يلعب في الحديقة",
]

# Query sentence
query = "الكتابة ممتعة"

# Extract embeddings for the query
query_emb = model(query)

# Function to compute cosine similarity
def cosine_similarity(vec1, vec2):
    vec1, vec2 = np.array(vec1[0][0]), np.array(vec2[0][0])  # Extract embeddings from list
    return np.dot(vec1, vec2) / (norm(vec1) * norm(vec2))

# Compare the query with each sentence in the dataset
threshold = 0.87
matches = []
for sentence in sentences:
    sentence_emb = model(sentence)  # Extract embedding for the sentence
    similarity = cosine_similarity(query_emb, sentence_emb)  # Compute similarity
    if similarity >= threshold:
        matches.append((sentence, similarity))

# Display the results
if matches:
    print("Matching sentences:")
    for match, score in matches:
        print(f"Sentence: {match}, Similarity: {score:.2f}")
else:
    print("No matches found.")
