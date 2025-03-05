# Use official Python image
FROM python:3.11

# Set the working directory inside the container
WORKDIR /app

# Copy the dependencies file first
COPY requirements.txt .

# Install dependencies globally (No venv needed)
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files into the container
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
