import streamlit as sl
import snowflake_functions
import pandas as pd

sl.header('Schema Music')

# Interactive table based on Snowflake
all_track_data = snowflake_functions.get_all_track_data(sl.secrets["snowflake"])
all_track_data.set_index('Song Title', inplace=True)
search_title = sl.text_input('Search by track name')
if search_title:
    all_track_data = all_track_data.loc[all_track_data.index.str.contains(
        search_title, case=False)]

    
dropdown_value = sl.selectbox(
    'Search by artist name', all_track_data['Artist'].unique())

if dropdown_value:
    all_track_data = all_track_data.loc[all_track_data['Artist']
                                        == dropdown_value]

sort_by_popularity = sl.checkbox('Sort by popularity')

sort_order = sl.radio('Sort order', ['Ascending', 'Descending'])
if sort_by_popularity:
    if sort_order == 'Ascending':
        all_track_data = all_track_data.sort_values(by='Popularity')
    else:
        all_track_data = all_track_data.sort_values(
            by='Popularity', ascending=False)


sl.dataframe(all_track_data)


# Email Subscription part
sl.write('If you want to get weekly updates of #daily-music and get to know a bunch of fun stats, subscribe to the mailing list!')
email = sl.text_input('', value='example@example.com')
if sl.button('Subscribe'):
    sl.write(snowflake_functions.add_email_to_mailing_list(
        email, sl.secrets["snowflake"]))
