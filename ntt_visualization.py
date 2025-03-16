import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

def ntt(A, w, p):
    """
    Number Theoretic Transform (NTT) of sequence A.
    """
    n = len(A)
    F = [0] * n
    for k in range(n):
        for j in range(n):
            F[k] = (F[k] + A[j] * pow(w, j * k, p)) % p
    return F

def intt(B, w, p):
    """
    Inverse Number Theoretic Transform (INTT) of sequence B.
    """
    n = len(B)
    w_inv = pow(w, p - 2, p)  # Inverse of w modulo p
    inv_n = pow(n, p - 2, p)  # Inverse of n modulo p
    A = [0] * n
    for j in range(n):
        for k in range(n):
            A[j] = (A[j] + B[k] * pow(w_inv, j * k, p)) % p
        A[j] = (A[j] * inv_n) % p
    return A

def convolve_power(G, a, w, p):
    """
    Compute G^{*a}, the sequence G convolved with itself a times.
    """
    F_G = ntt(G, w, p)           # Transform G to frequency domain
    F_Ga = [pow(f, a, p) for f in F_G]  # Pointwise exponentiation
    Ga = intt(F_Ga, w, p)        # Transform back to time domain
    return Ga

def find_primitive_root(n, p):
    """
    Find a primitive n-th root of unity modulo p.
    """
    # For n=2 and p=1001, we need w^2 ≡ 1 (mod 1001) and w ≠ 1
    # w = 1000 works because 1000^2 = 1,000,000 ≡ 1 (mod 1001)
    return 1000

# Parameters
p = 257  # Prime modulus
n = 2     # Sequence length (must divide p-1)
w = find_primitive_root(n, p)  # Primitive n-th root of unity

# Choose initial G with 2 elements
x, y = 113, 2  # Example values
G = [x, y]

# Choose a secret exponent
a = 256  # Number of convolutions to visualize

# Compute all convolutions from G^{*1} to G^{*a}
convolution_points = [G]  # Start with G^{*1} (which is just G)
for i in range(2, a + 1):
    convolution_points.append(convolve_power(G, i, w, p))

# Extract x and y coordinates for plotting
x_coords = [point[0] for point in convolution_points]
y_coords = [point[1] for point in convolution_points]

# Create visualization
plt.figure(figsize=(10, 10))
plt.scatter(x_coords, y_coords, c=range(len(x_coords)), cmap='viridis', 
            s=100, alpha=0.7, edgecolors='black')

# Add labels for each point
for i, (x, y) in enumerate(zip(x_coords, y_coords), 1):
    plt.annotate(f'G^{{{i}}}', (x, y), xytext=(5, 5), textcoords='offset points')

# Connect points with lines to show progression
plt.plot(x_coords, y_coords, 'b-', alpha=0.3)

# Highlight the first and last points
plt.scatter([x_coords[0]], [y_coords[0]], color='red', s=150, label='G (start)', zorder=5)
plt.scatter([x_coords[-1]], [y_coords[-1]], color='green', s=150, label=f'G^{{{a}}} (end)', zorder=5)

# Set plot limits and labels
plt.xlim(0, p)
plt.ylim(0, p)
plt.xlabel('First element of sequence (x)')
plt.ylabel('Second element of sequence (y)')
plt.title(f'Visualization of G^{{*i}} convolutions for i=1 to {a}, with G=[{x}, {y}]')
plt.grid(True, alpha=0.3)
plt.legend()

# Create a dynamic version with animation
fig, ax = plt.subplots(figsize=(10, 10))

def init():
    ax.set_xlim(0, p)
    ax.set_ylim(0, p)
    ax.set_xlabel('First element of sequence (x)')
    ax.set_ylabel('Second element of sequence (y)')
    ax.set_title(f'Progression of G^{{*i}} through convolutions (p={p})')
    ax.grid(True, alpha=0.3)
    return []

def update(frame):
    ax.clear()
    ax.set_xlim(0, p)
    ax.set_ylim(0, p)
    ax.set_xlabel('First element of sequence (x)')
    ax.set_ylabel('Second element of sequence (y)')
    ax.set_title(f'Progression of G^{{*i}} through convolutions (p={p})')
    ax.grid(True, alpha=0.3)
    
    # Plot all points up to current frame
    ax.scatter(x_coords[:frame+1], y_coords[:frame+1], 
               c=range(frame+1), cmap='viridis', s=100, alpha=0.7, edgecolors='black')
    
    # Connect points
    ax.plot(x_coords[:frame+1], y_coords[:frame+1], 'b-', alpha=0.3)
    
    # Label each point
    for i, (x, y) in enumerate(zip(x_coords[:frame+1], y_coords[:frame+1]), 1):
        ax.annotate(f'G^{{{i}}}', (x, y), xytext=(5, 5), textcoords='offset points')
    
    # Highlight the first point
    ax.scatter([x_coords[0]], [y_coords[0]], color='red', s=150, label='G (start)', zorder=5)
    
    # Highlight current point
    if frame > 0:
        ax.scatter([x_coords[frame]], [y_coords[frame]], color='green', 
                   s=150, label=f'G^{{{frame+1}}}', zorder=5)
    
    ax.legend()
    return []

# Create animation
ani = FuncAnimation(fig, update, frames=len(x_coords), init_func=init, blit=True, interval=1000)

# Save both figures
plt.figure(1)
plt.savefig('convolution_plot_static.png', dpi=300, bbox_inches='tight')
ani.save('convolution_progression.gif', writer='pillow', fps=1, dpi=100)

# Save a lower resolution version
ani.save('convolution_progression_lowres.gif', writer='pillow', fps=1, dpi=50)

plt.show()

# Print the sequence of convolutions
print("Sequence of convolutions:")
for i, point in enumerate(convolution_points, 1):
    print(f"G^{{{i}}} = {point}") 
