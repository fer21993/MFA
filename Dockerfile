FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5003
ENV MONGO_URI="mongodb+srv://2022371103:Minyoon93@cluster0.cbdtd0g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
ENV FLASK_ENV=production
CMD ["python", "app.py"]