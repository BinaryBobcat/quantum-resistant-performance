import random
import os
import string

def generate_random_text(seed, length=100):
    # use random function with set seed to generated random text
    rng = random.Random(seed)
    
    # generate plaintext files 
    chars = string.ascii_letters + string.digits + string.punctuation + ' ' * 10  # More spaces for readability
    return ''.join(rng.choice(chars) for _ in range(length))

def create_random_files(num_files, base_seed, output_dir):
    # create dir if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # generate files with random content
    for i in range(1, num_files + 1):
        # switch the seed per file but be derived off the base seed
        file_seed = base_seed + i
        
        # generate the random content in a certain range 50->500
        file_rng = random.Random(file_seed)
        content_length = file_rng.randint(50, 500)
        content = generate_random_text(file_seed, content_length)
        
        # Write to file
        filename = f"{output_dir}/{i:01d}"
        with open(filename, 'w') as f:
            f.write(content)
        
        print(f"Created file: {filename}")

if __name__ == "__main__":

    seed = 42
    dir = "ciphertexts"
    num_of_files = 100
    
    # fire main function to make the random files
    create_random_files(num_of_files, seed, dir)
    
    print(f"\nCompleted! Generated 100 random text files in "+dir+" directory.")
