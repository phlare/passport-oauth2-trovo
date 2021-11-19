/**
 * Parse profile.
 *
 * Parses user profiles as fetched from Trovo
 * https://developer.trovo.live/docs/APIs.html#_5-8-get-user-info
 * userId: '104753454',
     userName: 'phlaretv',
     nickName: 'phlaretv',
     email: 'phlarebot@gmail.com',
     profilePic:
      'https://headicon.trovo.live/user/fzut4bqaaaaab747xg47qwngcy.png?ext=png&t=2',
     info:
      'I’m a husband, a father, an engineer, and a gamer.  I\'m a variety streamer and aim to branch out into some new games.  \n\nSome of my favorites to stream are New World, Minecraft, Cyberpunk, Grand Theft Auto, Red Dead Redemption, and all sorts of others.',
     channelId: '104753454',
 *
 *
 * @param {object|string} json
 * @return {object}
 * @access public
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }
  var profile = {};
  
  profile.id = json.userId;
  profile.displayName = json.nickName;
  profile.name = json.userName;
  profile.email = json.email;
  if (json.profilePic) {
    profile.image = json.profilePic;
  }
  profile.info = json.info;
  profile.channelId = json.channelId;

  return profile;
};