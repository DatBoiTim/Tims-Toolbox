FROM python:3
ADD requirements.txt /
RUN pip install -r requirements.txt
ADD PwnCheckContainerized.py /
CMD ["python","./PwnCheckContainerized.py"]
EXPOSE 12000
EXPOSE 636
# LDAPS operates on Port 636