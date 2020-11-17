# Data Visualization with Plotly and Pandas
# Source : https://dev.socrata.com/blog/2016/02/02/plotly-pandas.html


'''
import matplotlib
import cufflinks as cf
# import plotly
import plotly.offline as py
from plotly.offline import plot
import plotly.graph_objs as go

fig = go.Figure(data=go.Bar(y=[2, 3, 1]))
# fig.show()

import json
import pandas as pd

with open('C:/Users/rbd218/PycharmProjects/nod/script_results/domainscores1027_norm.json', 'r') as f:
    data = json.load(f)
    nod_data = pd.DataFrame(data)

features = nod_data.columns

# print(features)
from plotly.offline import plot
entropy = pd.concat([nod_data.entropy])
# entropy.value_counts().plot(kind='bar')
entropy.value_counts().iplot(kind='bar')
'''

# SOURCE: https://plotly.com/python/v3/compare-webgl-svg/
import chart_studio.plotly as py
import plotly.graph_objs as go

'''
import numpy as np

N = 75000
trace = go.Scattergl(
    x=np.random.randn(N),
    y=np.random.randn(N),
    mode='markers',
    marker=dict(
        line=dict(
            width=1,
            color='#404040')
    )
)
data = [trace]
layout = dict(title='WEBGL')
fig = dict(data=data, layout=layout)
py.iplot(data, filename='webgl75')
'''

'''
# SOURCE: https://plotly.com/python/webgl-vs-svg/
import plotly.graph_objects as go

import numpy as np

N = 100000

# Create figure
fig = go.Figure()

fig.add_trace(
    go.Scattergl(
        x = np.random.randn(N),
        y = np.random.randn(N),
        mode = 'markers',
        marker = dict(
            line = dict(
                width = 1,
                color = 'DarkSlateGrey')
        )
    )
)

fig.show()
'''

import json
import pandas as pd
import plotly.express as px

df = px.data.iris()

with open('C:/Users/rbd218/PycharmProjects/nod/script_results/domainscores1027_norm.json', 'r') as f:
    data = json.load(f)
    nod_data = pd.DataFrame(data)

''' 
# Source : https://plotly.com/r/text-and-annotations/#multiple-annotations
# Source : 
    import numpy as np

    # create the bins
    counts, bins = np.histogram(nod_data.domaintools, bins=range(0, 1, 5))
    bins = 0.001 * (bins[:-1] + bins[1:])

    fig = px.bar(x=bins, y=counts, text='counts', labels={'x':'total_bill', 'y':'count'})
    fig.update_traces(texttemplate='%{text:.2s}', textposition='outside')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide')
    fig.show()
'''

'''
Index(['malware_domain', 'phishtank', 'domaintools', 'knujon', 'entropy',
       'registrar_prices', 'resolver', 'spamhaus_reg', 'spamhaus_tld',
       'alexatop', 'domain_age', 'DomainName'],
      dtype='object')
'''
features = nod_data.columns

# print(features)
from plotly.offline import plot

# all_num_data = pd.concat([nod_data.domaintools], [nod_data.knujon])
domaintools = pd.concat([nod_data.domaintools])
knujon = pd.concat([nod_data.knujon])
entropy = pd.concat([nod_data.entropy])
registrar_prices = pd.concat([nod_data.registrar_prices])
resolver = pd.concat([nod_data.resolver])
# spamhaus_tld = pd.concat([nod_data.spamhaus_tld])
domain_age = pd.concat([nod_data.spamhaus_tld])
# fig = go.Figure(data=entropy)
# fig.show()


'''
# Overlay both histograms
fig0.update_layout(barmode='overlay')
# Reduce opacity to see both histograms
fig0.update_traces(opacity=0.75)
fig0.show()
'''


fig1 = px.histogram(domaintools)
fig1.show()

fig2 = px.histogram(knujon)
fig2.show()

fig3 = px.histogram(entropy)
fig3.show()

fig4 = px.histogram(registrar_prices)
fig4.show()

fig5 = px.histogram(resolver)
fig5.show()

fig5 = px.histogram(spamhaus_tld)
fig5.show()

fig6 = px.histogram(domain_age)
fig6.show()
