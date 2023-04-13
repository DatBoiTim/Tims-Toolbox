FROM python:3
ADD requirements.txt /
RUN pip install -r requirements.txt
ADD PwnCheckContainerized.py /
CMD ["python3","./PwnCheckContainerized.py"]
EXPOSE 636
# LDAPS operates on Port 636